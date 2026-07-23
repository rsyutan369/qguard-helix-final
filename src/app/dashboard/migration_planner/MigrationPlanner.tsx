'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Activity,
  AlertTriangle,
  Banknote,
  BrainCircuit,
  Boxes,
  Building2,
  CalendarClock,
  CheckCircle2,
  ChevronRight,
  Clock,
  Download,
  EyeOff,
  FileText,
  FlaskConical,
  Gauge,
  Layers,
  Radio,
  RefreshCw,
  Rocket,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Target,
  Workflow,
  type LucideIcon,
} from 'lucide-react';
import { useAuth } from '@/contexts/auth-context';
import { useMigrationPlan, type MigrationStrategy } from '@/hooks/use-migration-plan';
import { clearMigrationHandoff, readMigrationHandoff, type MigrationHandoff } from '@/app/dashboard/quantum-readiness/_advisor';
import { WorkflowRail } from '@/components/workflow/WorkflowRail';
import {
  Badge,
  BarList,
  EmptyState,
  HeaderButton,
  MetricCard,
  Panel,
  PrimaryButton,
  Ring,
  SectionTitle,
  compactFmt,
  currencyFmt,
  integerFmt,
  longDate,
  percentLabel,
  readinessTone,
  riskTone,
  severityColor,
  RED,
  ORANGE,
  AMBER,
  GOLD,
  GREEN,
  EMERALD,
  TEAL,
  BLUE,
  CYAN,
  VIOLET,
} from '@/app/dashboard/quantum-readiness/_shared';

const SLATEISH = '#64748B';

/* ------------------------------------------------------------------ */
/* Approval workflow — real migration_plans rows. Submitting creates a */
/* pending_approval plan; approve/reject records the decision. The     */
/* 9-stage 'Approve' stage and the platform WorkflowRail read the same */
/* rows, so every status indicator stays consistent.                   */
/* ------------------------------------------------------------------ */
interface ApprovalPlan {
  id: string;
  name: string;
  status: string;
  createdAt: string;
  updatedAt: string;
  submittedBy: string;
  approval: { decision: string; decidedBy: string; decidedAt: string; reason: string } | null;
}

const PLAN_STATUS_TONES: Record<string, string> = {
  approved: EMERALD,
  pending_approval: AMBER,
  rejected: RED,
};

function ApprovalWorkflowPanel({ onDecision }: { onDecision: () => void }) {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [plans, setPlans] = useState<ApprovalPlan[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [rejectingId, setRejectingId] = useState<string | null>(null);
  const [reason, setReason] = useState('');

  const loadPlans = useCallback(async () => {
    if (!token) return;
    try {
      const response = await fetch('/api/v1/migration-planner/plans', { headers: { Authorization: `Bearer ${token}` } });
      const payload = await response.json().catch(() => ({}));
      if (response.ok) setPlans(payload.data || []);
    } catch {
      /* panel is auxiliary — keep the page alive */
    }
  }, [token]);

  useEffect(() => {
    void loadPlans();
  }, [loadPlans]);

  const post = useCallback(
    async (path: string, body: unknown, okText: string) => {
      if (!token) return;
      setBusy(true);
      setMessage(null);
      try {
        const response = await fetch(`/api/v1/migration-planner${path}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify(body),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
        setMessage(okText);
        setRejectingId(null);
        setReason('');
        await loadPlans();
        onDecision();
      } catch (err) {
        setMessage(err instanceof Error ? err.message : 'Action failed');
      } finally {
        setBusy(false);
      }
    },
    [token, loadPlans, onDecision],
  );

  const pending = plans.filter((p) => /pending/i.test(p.status));
  const approved = plans.filter((p) => /approved/i.test(p.status));

  return (
    <Panel className="p-5">
      <SectionTitle
        suffix={
          <Badge color={approved.length ? EMERALD : pending.length ? AMBER : SLATEISH}>
            {approved.length ? `${approved.length} approved` : pending.length ? `${pending.length} awaiting approval` : 'No plan submitted'}
          </Badge>
        }
      >
        Approval Workflow
      </SectionTitle>
      <p className="mb-3 text-xs text-white/55">
        Executive sign-off gate before Live Migration execution. Submitting records a real migration plan; approval
        decisions are stamped with the approver and timestamp and flow to the workflow rail on every dashboard.
      </p>
      {message ? <div className="mb-3 rounded border border-white/10 bg-white/[0.04] px-3 py-2 text-[11px] text-white/70">{message}</div> : null}
      <div className="mb-3">
        <PrimaryButton icon={ScrollText} onClick={() => void post('/plans', {}, 'Plan submitted for approval.')} disabled={busy || !user}>
          {busy ? 'Working…' : 'Submit Plan for Approval'}
        </PrimaryButton>
      </div>
      {plans.length ? (
        <div className="space-y-2">
          {plans.slice(0, 6).map((plan) => {
            const tone = PLAN_STATUS_TONES[plan.status.toLowerCase()] || SLATEISH;
            return (
              <div key={plan.id} className="rounded-md border border-white/8 bg-white/[0.02] px-3 py-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="truncate text-xs font-bold text-white/85">{plan.name}</span>
                      <Badge color={tone}>{plan.status.replace(/_/g, ' ')}</Badge>
                    </div>
                    <div className="mt-0.5 text-[10px] text-white/40">
                      {plan.submittedBy ? `Submitted by ${plan.submittedBy} · ` : ''}
                      {longDate(plan.updatedAt || plan.createdAt)}
                      {plan.approval ? ` · ${plan.approval.decision === 'approve' ? 'Approved' : 'Rejected'} by ${plan.approval.decidedBy}${plan.approval.reason ? ` — ${plan.approval.reason}` : ''}` : ''}
                    </div>
                  </div>
                  {/pending/i.test(plan.status) ? (
                    <div className="flex shrink-0 items-center gap-2">
                      <HeaderButton icon={CheckCircle2} onClick={() => void post(`/plans/${encodeURIComponent(plan.id)}/approval`, { decision: 'approve' }, 'Plan approved — execution unlocked.')}>
                        Approve
                      </HeaderButton>
                      <HeaderButton icon={ShieldAlert} onClick={() => setRejectingId(rejectingId === plan.id ? null : plan.id)}>
                        Reject
                      </HeaderButton>
                    </div>
                  ) : null}
                </div>
                {rejectingId === plan.id ? (
                  <div className="mt-2 flex flex-wrap items-center gap-2">
                    <input
                      value={reason}
                      onChange={(e) => setReason(e.target.value)}
                      placeholder="Rejection reason (required)"
                      className="h-9 flex-1 rounded-md border border-white/10 bg-black/30 px-3 text-xs text-white outline-none placeholder:text-white/30 focus:border-red-400/50"
                    />
                    <PrimaryButton
                      onClick={() => reason.trim() && void post(`/plans/${encodeURIComponent(plan.id)}/approval`, { decision: 'reject', reason: reason.trim() }, 'Plan rejected — revise and resubmit.')}
                      disabled={busy || !reason.trim()}
                    >
                      Confirm Rejection
                    </PrimaryButton>
                  </div>
                ) : null}
              </div>
            );
          })}
        </div>
      ) : (
        <EmptyState label="No migration plans submitted yet." hint="Submit the current roadmap for executive approval to unlock Live Migration execution." />
      )}
    </Panel>
  );
}

const STAGE_ICONS: Record<string, LucideIcon> = {
  discover: Boxes,
  analyze: Activity,
  prioritize: Target,
  simulate: FlaskConical,
  plan: Workflow,
  approve: CheckCircle2,
  execute: Rocket,
  validate: ShieldCheck,
  optimize: Gauge,
};

const POSTURE_COLOR: Record<string, string> = { pqc: EMERALD, hybrid: AMBER, vulnerable: RED };
const usd = (n: number) => (n ? currencyFmt(n) : 'Evidence Not Available');

function levelTone(level: string): string {
  const l = (level || '').toLowerCase();
  if (l.includes('critical')) return RED;
  if (l.includes('high') || l.includes('elevated')) return ORANGE;
  if (l.includes('medium') || l.includes('moderate')) return GOLD;
  if (l.includes('low')) return GREEN;
  return TEAL;
}

export default function MigrationPlanner() {
  const navigate = useNavigate();
  const { session } = useAuth();
  const { plan, state, error, sseConnected, refresh } = useMigrationPlan();
  const [strategyKey, setStrategyKey] = useState('balanced');
  const [exporting, setExporting] = useState<string | null>(null);
  const [heatmapFilter, setHeatmapFilter] = useState<string>('all');
  const [notice, setNotice] = useState<string | null>(null);
  // Roadmap handed off from the AI Migration Advisor™ (localStorage payload —
  // the exact waves/prioritization/rollback plan the advisor displayed).
  const [handoff, setHandoff] = useState<MigrationHandoff | null>(() => readMigrationHandoff());

  const dismissHandoff = useCallback(() => {
    clearMigrationHandoff();
    setHandoff(null);
  }, []);

  const selectedStrategy = useMemo<MigrationStrategy | undefined>(
    () => plan.strategies.find((s) => s.key === strategyKey) || plan.strategies.find((s) => s.recommended) || plan.strategies[0],
    [plan.strategies, strategyKey],
  );

  const generate = useCallback(
    async (format: 'pdf' | 'docx' | 'json', kind: 'migration' | 'executive') => {
      const token = session?.access_token;
      if (!token || !plan.hasData) {
        setNotice('No assessment evidence available to generate a report.');
        return;
      }
      setExporting(`${kind}-${format}`);
      setNotice(null);
      try {
        const snapRes = await fetch('/api/v1/quantum-readiness', { headers: { Authorization: `Bearer ${token}` } });
        const snapshot = (await snapRes.json()).data;
        const [{ buildReport }, { exportReport, downloadResult }, { brandingSchema }] = await Promise.all([
          import('@/services/reporting/ReportEngine'),
          import('@/services/reporting/ReportExporter'),
          import('@/services/reporting/schemas/ReportSchema'),
        ]);
        const branding = brandingSchema.parse({ reportVersion: '1.0' });
        const report = buildReport({ snapshot, branding, kind, generatedBy: 'Migration Planner', withCharts: format !== 'json' });
        const result = await exportReport(report, format);
        downloadResult(result);
        setNotice(`${kind === 'migration' ? 'Migration' : 'Executive'} report (${format.toUpperCase()}) generated.`);
      } catch (err) {
        setNotice(err instanceof Error ? err.message : 'Report generation failed');
      } finally {
        setExporting(null);
      }
    },
    [session, plan.hasData],
  );

  const heatmapStates = [
    { label: 'Ready', value: plan.heatmap.ready, color: EMERALD },
    { label: 'Needs Validation', value: plan.heatmap.needsValidation, color: AMBER },
    { label: 'Needs Upgrade', value: plan.heatmap.needsUpgrade, color: ORANGE },
    { label: 'Blocked', value: plan.heatmap.blocked, color: RED },
    { label: 'Unknown', value: plan.heatmap.unknown, color: VIOLET },
  ];
  const filteredHeatmapRows = plan.heatmap.rows.filter((r) => heatmapFilter === 'all' || r.state === heatmapFilter);

  return (
    <div className="min-h-screen bg-[#030711] px-4 py-5 text-white sm:px-5 lg:px-6">
      <div className="mx-auto max-w-[1560px] space-y-4">
        <WorkflowRail activeStage="planning" />
        {/* Header */}
        <header className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-2xl font-semibold text-white">Migration Planner™</h1>
              <Badge color={readinessTone(plan.hero.readinessScore)}>{plan.hero.readinessLevel}</Badge>
              <Badge color={plan.riskEngine.overall >= 50 ? RED : AMBER}>Migration Risk {plan.riskEngine.overall}/100</Badge>
            </div>
            <p className="mt-1 max-w-3xl text-sm text-white/58">
              Enterprise Post-Quantum Migration Management — discover, analyze, prioritize, simulate, plan, approve, execute, validate and optimize. Every metric is real, tenant-scoped and mirrors your scanned assets.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2.5">
            <HeaderButton icon={Radio} active={sseConnected}>{sseConnected ? 'Live' : 'Syncing'}</HeaderButton>
            <HeaderButton icon={RefreshCw} onClick={() => void refresh()}>Refresh</HeaderButton>
            <HeaderButton icon={BrainCircuit} onClick={() => navigate(plan.advisor.deepLink)}>AI Advisor</HeaderButton>
            <PrimaryButton icon={FileText} onClick={() => void generate('pdf', 'migration')} disabled={exporting !== null}>
              {exporting === 'migration-pdf' ? 'Generating…' : 'Migration Report'}
            </PrimaryButton>
          </div>
        </header>

        {error ? <div className="rounded-md border border-red-500/25 bg-red-500/10 px-4 py-3 text-sm text-red-200">{error}</div> : null}
        {notice ? <div className="rounded-md border border-blue-400/25 bg-blue-500/10 px-4 py-3 text-sm text-blue-100">{notice}</div> : null}
        {handoff ? (
          <div className="rounded-md border border-violet-400/30 bg-violet-500/[0.08] px-4 py-3">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="flex items-start gap-3">
                <span className="grid h-8 w-8 shrink-0 place-items-center rounded-md border border-violet-400/40 bg-violet-500/10 text-violet-300">
                  <BrainCircuit className="h-4 w-4" />
                </span>
                <div className="min-w-0">
                  <div className="text-sm font-bold text-white">
                    Roadmap received from AI Migration Advisor™
                    <span className="ml-2 text-[11px] font-semibold text-white/45">{longDate(handoff.generatedAt)} · confidence {handoff.confidencePct}%</span>
                  </div>
                  <p className="mt-0.5 text-xs text-white/65">
                    <span className="font-semibold text-violet-200">{handoff.recommendation}</span>
                    {' — '}
                    {handoff.waves.length} wave(s) · {handoff.assetPrioritization.length} prioritized asset(s) · {handoff.rollbackStrategy.length} rollback runbook(s)
                    {handoff.estimates.migrationTimelineWeeks ? ` · ${integerFmt(handoff.estimates.migrationTimelineWeeks)}w` : ''}
                    {handoff.estimates.migrationCostUsd ? ` · ${currencyFmt(handoff.estimates.migrationCostUsd)}` : ''}
                  </p>
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {handoff.waves.map((wave) => (
                      <span key={wave.wave} className="rounded border border-white/10 bg-black/20 px-1.5 py-0.5 text-[10px] font-semibold text-white/55">
                        W{wave.wave} {wave.name} · {wave.durationWeeks}w · −{wave.riskReductionPct}%
                      </span>
                    ))}
                  </div>
                </div>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                <HeaderButton icon={Download} onClick={() => {
                  const blob = new Blob([JSON.stringify(handoff, null, 2)], { type: 'application/json' });
                  const url = URL.createObjectURL(blob);
                  const anchor = document.createElement('a');
                  anchor.href = url;
                  anchor.download = `migration-roadmap-handoff-${new Date().toISOString().slice(0, 10)}.json`;
                  anchor.click();
                  URL.revokeObjectURL(url);
                }}>
                  Download
                </HeaderButton>
                <HeaderButton icon={CheckCircle2} onClick={dismissHandoff}>
                  Acknowledge
                </HeaderButton>
              </div>
            </div>
            <p className="mt-2 text-[10px] leading-snug text-white/35">
              The planner's stages, waves and costs below derive from the same live evidence engine — the handed-off roadmap and this plan reconcile by construction. Acknowledging clears the handoff.
            </p>
          </div>
        ) : null}
        {!plan.hasData && state === 'success' ? (
          <div className="rounded-md border border-amber-400/25 bg-amber-400/[0.07] px-4 py-3 text-sm text-amber-100/90">
            No assessment evidence found for this tenant. Run a PQC discovery scan to populate the migration plan.
          </div>
        ) : null}

        {/* 9-stage workflow */}
        <Panel className="p-5">
          <SectionTitle suffix={<span className="hidden text-[11px] text-white/40 lg:inline">Discover → Analyze → Prioritize → Simulate → Plan → Approve → Execute → Validate → Optimize</span>}>Migration Workflow</SectionTitle>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-9">
            {plan.stages.map((stage, index) => {
              const Icon = STAGE_ICONS[stage.key] || Workflow;
              const tone = stage.status === 'Complete' ? EMERALD : stage.status === 'In Progress' ? GOLD : SLATEISH;
              return (
                <div key={stage.key} className="rounded-lg border border-white/8 bg-white/[0.025] p-3">
                  <div className="flex items-center justify-between">
                    <span className="grid h-7 w-7 place-items-center rounded-md border text-[11px] font-black" style={{ borderColor: `${tone}45`, color: tone, backgroundColor: `${tone}12` }}>
                      {stage.status === 'Complete' ? <CheckCircle2 className="h-4 w-4" /> : index + 1}
                    </span>
                    <Icon className="h-4 w-4 text-white/35" />
                  </div>
                  <div className="mt-2 text-xs font-bold text-white/85">{stage.label}</div>
                  <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-white/5">
                    <div className="h-full rounded-full transition-all" style={{ width: `${stage.progressPct}%`, backgroundColor: tone }} />
                  </div>
                  <div className="mt-1.5 flex items-center justify-between text-[9px] text-white/45">
                    <span>{stage.status}</span>
                    <span>{compactFmt(stage.assetCount)}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>

        {/* Approval workflow — executive sign-off gate */}
        <ApprovalWorkflowPanel onDecision={() => void refresh()} />

        {/* Executive hero metrics */}
        <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          {[
            { label: 'Migration Readiness', value: integerFmt(plan.hero.readinessScore), suffix: '/100', detail: plan.hero.readinessLevel, color: readinessTone(plan.hero.readinessScore), ring: plan.hero.readinessScore },
            { label: 'Assets Requiring Migration', value: integerFmt(plan.hero.assetsRequiringMigration), detail: `${integerFmt(plan.hero.vulnerableComponents)} vulnerable components`, color: RED, icon: Boxes },
            { label: 'Estimated Duration', value: plan.hero.durationLabel, detail: `${integerFmt(plan.hero.durationWeeks)} weeks`, color: BLUE, icon: CalendarClock },
            { label: 'Estimated Cost', value: plan.hero.costLabel, detail: 'Total program', color: EMERALD, icon: Banknote },
            { label: 'Potential Risk Reduction', value: percentLabel(plan.hero.riskReductionPct), detail: 'Across all waves', color: GREEN, ring: plan.hero.riskReductionPct },
            { label: 'HNDL Exposure', value: plan.hero.hndlExposure, detail: `${integerFmt(plan.hero.hndlScore)}/100`, color: levelTone(plan.hero.hndlExposure), icon: AlertTriangle },
            { label: 'PQC Adoption', value: percentLabel(plan.hero.pqcAdoption), detail: 'Quantum-safe coverage', color: CYAN, ring: plan.hero.pqcAdoption },
            { label: 'Critical Findings Remaining', value: integerFmt(plan.hero.criticalAssetsRemaining), detail: 'Highest priority', color: ORANGE, icon: ShieldAlert },
          ].map((kpi) => (
            <div key={kpi.label}><MetricCard {...kpi} /></div>
          ))}
        </motion.section>

        {/* AI Advisor + Risk Engine */}
        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-7">
            <SectionTitle suffix={<Badge color={VIOLET}>AI</Badge>}>AI Migration Advisor™</SectionTitle>
            {plan.advisor.recommendation ? (
              <div className="rounded-lg border border-violet-400/30 bg-gradient-to-br from-violet-500/10 to-transparent p-4">
                <div className="text-[10px] font-black uppercase tracking-wide text-violet-300/70">Top Recommendation</div>
                <div className="mt-1 text-lg font-bold text-white">{plan.advisor.recommendation}</div>
                <p className="mt-1.5 text-sm leading-relaxed text-white/60">{plan.advisor.reason}</p>
                <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
                  {([
                    ['Risk Reduction', percentLabel(plan.advisor.riskReductionPct), GREEN],
                    ['Est. Cost', usd(plan.advisor.costUsd), EMERALD],
                    ['Timeline', `${integerFmt(plan.advisor.timelineWeeks)}w`, BLUE],
                    ['Confidence', percentLabel(plan.advisor.confidencePct), VIOLET],
                  ] as Array<[string, string, string]>).map(([k, v, c]) => (
                    <div key={k} className="rounded-md border border-white/8 bg-black/20 p-2.5">
                      <div className="text-base font-semibold" style={{ color: c }}>{v}</div>
                      <div className="text-[10px] uppercase tracking-wide text-white/45">{k}</div>
                    </div>
                  ))}
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  <HeaderButton icon={Layers} onClick={() => navigate(plan.advisor.deepLink)}>Create Migration Wave</HeaderButton>
                  <HeaderButton icon={ScrollText} onClick={() => void generate('pdf', 'migration')}>Generate Playbook</HeaderButton>
                  <HeaderButton icon={EyeOff} onClick={() => navigate('/dashboard/harvest-now')}>Harvest Now Risk</HeaderButton>
                  <HeaderButton icon={FileText} onClick={() => void generate('pdf', 'executive')}>Executive Report</HeaderButton>
                </div>
              </div>
            ) : (
              <EmptyState label="No advisory yet." hint="Run a discovery scan to generate AI migration guidance." />
            )}
          </Panel>

          <Panel className="p-5 xl:col-span-5">
            <SectionTitle suffix={<Badge color={plan.riskEngine.overall >= 50 ? RED : AMBER}>{plan.riskEngine.overallLevel}</Badge>}>Migration Risk Engine™</SectionTitle>
            <div className="flex items-center gap-5">
              <Ring value={plan.riskEngine.overall} color={riskTone(plan.riskEngine.overall)} size={96} stroke={10}>
                <div>
                  <div className="text-2xl font-semibold text-white">{integerFmt(plan.riskEngine.overall)}</div>
                  <div className="text-[9px] uppercase tracking-wide text-white/45">Risk</div>
                </div>
              </Ring>
              <div className="flex-1 space-y-1.5">
                {plan.riskEngine.categories.map((cat) => (
                  <div key={cat.key} className="grid grid-cols-[1fr_auto] items-center gap-2 text-[11px]">
                    <div className="flex items-center gap-2">
                      <span className="w-28 truncate text-white/65">{cat.label}</span>
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/5">
                        <div className="h-full rounded-full" style={{ width: `${cat.score}%`, backgroundColor: riskTone(cat.score) }} />
                      </div>
                    </div>
                    <span className="font-mono text-white/70">{integerFmt(cat.score)}</span>
                  </div>
                ))}
              </div>
            </div>
            <p className="mt-3 text-[11px] leading-relaxed text-white/50">{plan.riskEngine.explanation}</p>
          </Panel>
        </section>

        {/* Strategy Simulator */}
        <Panel className="p-5">
          <SectionTitle suffix={<span className="text-[11px] text-white/40">Select a strategy to model outcomes</span>}>Migration Strategy Simulator™</SectionTitle>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {plan.strategies.map((strategy) => {
              const active = selectedStrategy?.key === strategy.key;
              return (
                <button
                  key={strategy.key}
                  type="button"
                  onClick={() => setStrategyKey(strategy.key)}
                  className={`rounded-lg border p-4 text-left transition ${active ? 'border-blue-400/50 bg-blue-500/10' : 'border-white/8 bg-white/[0.025] hover:border-blue-400/35'}`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-bold text-white">{strategy.name}</span>
                    {strategy.recommended ? <Badge color={GREEN}>Recommended</Badge> : null}
                  </div>
                  <p className="mt-1 text-[11px] leading-snug text-white/50">{strategy.summary}</p>
                  <div className="mt-3 grid grid-cols-3 gap-2 text-center">
                    <div><div className="text-sm font-bold" style={{ color: GREEN }}>{percentLabel(strategy.riskReductionPct)}</div><div className="text-[9px] uppercase text-white/40">Risk ↓</div></div>
                    <div><div className="text-sm font-bold text-white">{integerFmt(strategy.timelineWeeks)}w</div><div className="text-[9px] uppercase text-white/40">Time</div></div>
                    <div><div className="text-sm font-bold" style={{ color: EMERALD }}>{strategy.costUsd ? compactFmt(strategy.costUsd) : '—'}</div><div className="text-[9px] uppercase text-white/40">Cost</div></div>
                  </div>
                </button>
              );
            })}
          </div>
          {selectedStrategy ? (
            <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-7">
              {([
                ['Est. Cost', usd(selectedStrategy.costUsd), EMERALD],
                ['Timeline', `${integerFmt(selectedStrategy.timelineWeeks)} weeks`, BLUE],
                ['Risk Reduction', percentLabel(selectedStrategy.riskReductionPct), GREEN],
                ['Operational Risk', selectedStrategy.operationalRisk, levelTone(selectedStrategy.operationalRisk)],
                ['Downtime Prob.', percentLabel(selectedStrategy.downtimeProbabilityPct), GOLD],
                ['Compliance Impact', percentLabel(selectedStrategy.complianceImpactPct), CYAN],
                ['Success Prob.', percentLabel(selectedStrategy.successProbabilityPct), VIOLET],
              ] as Array<[string, string, string]>).map(([k, v, c]) => (
                <div key={k} className="rounded-md border border-white/8 bg-black/20 p-3">
                  <div className="text-sm font-semibold" style={{ color: c }}>{v}</div>
                  <div className="text-[10px] uppercase tracking-wide text-white/45">{k}</div>
                </div>
              ))}
            </div>
          ) : null}
        </Panel>

        {/* What-If + Waves */}
        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-5">
            <SectionTitle>What-If Analysis</SectionTitle>
            <div className="space-y-2.5">
              {plan.whatIf.map((w) => (
                <div key={w.scenario} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
                  <div className="text-xs font-bold text-white/85">{w.scenario}</div>
                  <div className="mt-2 flex flex-wrap gap-3 text-[11px]">
                    <span style={{ color: GREEN }}>Risk ↓ {percentLabel(w.riskReductionPct)}</span>
                    <span className="text-white/55">{usd(w.costUsd)}</span>
                    <span className="text-white/55">{w.timelineLabel}</span>
                    <span style={{ color: CYAN }}>Compliance +{percentLabel(w.complianceIncreasePct)}</span>
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          <Panel className="p-5 xl:col-span-7">
            <SectionTitle suffix={<span className="text-[11px] text-white/40">{plan.waves.length} waves</span>}>Migration Waves</SectionTitle>
            <div className="overflow-x-auto">
              <table className="min-w-[640px] w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.08em] text-white/35">
                    <th className="pb-2.5 font-black">Wave</th><th className="pb-2.5 font-black">Focus</th><th className="pb-2.5 font-black">Priority</th>
                    <th className="pb-2.5 font-black">Owner</th><th className="pb-2.5 font-black">Dur</th><th className="pb-2.5 font-black">Cost</th>
                    <th className="pb-2.5 font-black">Risk ↓</th><th className="pb-2.5 font-black">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {plan.waves.map((w) => (
                    <tr key={w.wave} className="border-b border-white/5 text-white/70">
                      <td className="py-2.5 font-bold text-white/85">W{w.wave}</td>
                      <td className="py-2.5">{w.name}</td>
                      <td className="py-2.5"><span className="rounded px-1.5 py-0.5 text-[9px] font-black" style={{ color: levelTone(w.priority), backgroundColor: `${levelTone(w.priority)}1a` }}>{w.priority}</span></td>
                      <td className="max-w-[120px] truncate py-2.5">{w.owner}</td>
                      <td className="py-2.5 font-mono">{integerFmt(w.durationWeeks)}w</td>
                      <td className="py-2.5 font-mono">{w.costUsd ? compactFmt(w.costUsd) : '—'}</td>
                      <td className="py-2.5 font-mono" style={{ color: GREEN }}>{percentLabel(w.riskReductionPct)}</td>
                      <td className="py-2.5">{w.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        </section>

        {/* Shared Responsibility dependency-ordered roadmap */}
        {plan.sharedResponsibility && plan.sharedResponsibility.hasData ? (
          <Panel className="p-5">
            <SectionTitle
              suffix={
                <HeaderButton icon={ChevronRight} onClick={() => navigate('/dashboard/migration-intelligence')}>
                  Open Migration Intelligence™
                </HeaderButton>
              }
            >
              Shared Responsibility Roadmap — Dependency-Ordered
            </SectionTitle>
            <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
              {([
                ['Overall', plan.sharedResponsibility.readiness.overall.score, GOLD],
                ['Customer', plan.sharedResponsibility.readiness.customer.score, CYAN],
                ['Provider', plan.sharedResponsibility.readiness.provider.score, BLUE],
                ['Ecosystem', plan.sharedResponsibility.readiness.ecosystem.score, VIOLET],
              ] as Array<[string, number, string]>).map(([label, score, color]) => (
                <div key={label} className="rounded-md border border-white/8 bg-white/[0.02] p-3 text-center">
                  <div className="text-[9px] font-black uppercase tracking-wide text-white/40">{label}</div>
                  <div className="mt-1 text-xl font-semibold" style={{ color }}>{integerFmt(score)}</div>
                  <div className="text-[9px] text-white/35">/100</div>
                </div>
              ))}
            </div>
            <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
              {plan.sharedResponsibility.waves.map((wave) => {
                const tone = wave.domain === 'customer' ? CYAN : wave.domain === 'provider' ? BLUE : wave.domain === 'ecosystem' ? VIOLET : SLATEISH;
                const statusColor = wave.status === 'ready' ? EMERALD : wave.status === 'complete' ? GREEN : wave.status === 'blocked' ? RED : AMBER;
                return (
                  <div key={wave.wave} className="flex items-center gap-3 rounded-md border border-white/8 bg-white/[0.02] p-2.5">
                    <span className="grid h-7 w-7 shrink-0 place-items-center rounded-md text-[11px] font-black" style={{ backgroundColor: `${tone}1a`, color: tone }}>{wave.wave}</span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 text-xs font-bold text-white/85">
                        <span className="truncate">{wave.name}</span>
                        <span className="font-mono text-[10px] text-white/40">{integerFmt(wave.findingCount)}</span>
                      </div>
                      <div className="truncate text-[10px] text-white/40">{wave.description}</div>
                    </div>
                    <span className="rounded px-1.5 py-0.5 text-[9px] font-black uppercase" style={{ color: statusColor, backgroundColor: `${statusColor}1a` }}>{wave.status}</span>
                  </div>
                );
              })}
            </div>
            <p className="mt-3 text-[11px] text-white/40">
              Waves are ordered by dependency: customer-controlled work (1–4) proceeds now; provider and ecosystem waves (5–7)
              track upstream roadmaps and never block the customer-controlled path. Full ownership detail lives in Migration Intelligence™.
            </p>
          </Panel>
        ) : null}

        {/* Readiness Breakdown + Business Impact */}
        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-7">
            <SectionTitle>Migration Readiness Breakdown</SectionTitle>
            <div className="overflow-x-auto">
              <table className="min-w-[560px] w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.08em] text-white/35">
                    <th className="pb-2.5 font-black">Domain</th><th className="pb-2.5 font-black">Score</th><th className="pb-2.5 font-black">Risk</th>
                    <th className="pb-2.5 font-black">Complexity</th><th className="pb-2.5 font-black">Owner</th>
                  </tr>
                </thead>
                <tbody>
                  {plan.readinessDomains.map((d) => (
                    <tr key={d.domain} className="border-b border-white/5 text-white/70">
                      <td className="py-2 font-medium text-white/82">{d.domain}</td>
                      <td className="py-2">
                        <span className="inline-flex items-center gap-2">
                          <span className="font-mono" style={{ color: readinessTone(d.score) }}>{integerFmt(d.score)}</span>
                          <span className="h-1.5 w-16 overflow-hidden rounded-full bg-white/5"><span className="block h-full rounded-full" style={{ width: `${d.score}%`, backgroundColor: readinessTone(d.score) }} /></span>
                        </span>
                      </td>
                      <td className="py-2 font-bold" style={{ color: levelTone(d.riskLevel) }}>{d.riskLevel}</td>
                      <td className="py-2">{d.complexity}</td>
                      <td className="max-w-[120px] truncate py-2">{d.owner}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <Panel className="p-5 xl:col-span-5">
            <SectionTitle suffix={<Building2 className="h-4 w-4 text-white/40" />}>Business Impact Analysis</SectionTitle>
            <div className="grid grid-cols-2 gap-2.5">
              {([
                ['Customer-Facing Systems', integerFmt(plan.businessImpact.customerFacingSystems), BLUE],
                ['Mission-Critical Systems', integerFmt(plan.businessImpact.missionCriticalSystems), RED],
                ['Third-Party Dependencies', integerFmt(plan.businessImpact.thirdPartyDependencies), VIOLET],
                ['Revenue Impact', plan.businessImpact.revenueImpact, levelTone(plan.businessImpact.revenueImpact)],
                ['Compliance Impact', plan.businessImpact.complianceImpact, levelTone(plan.businessImpact.complianceImpact)],
                ['Operational Impact', plan.businessImpact.operationalImpact, levelTone(plan.businessImpact.operationalImpact)],
                ['HNDL Exposure', plan.businessImpact.hndlExposure, levelTone(plan.businessImpact.hndlExposure)],
                ['Exposure Window', plan.businessImpact.quantumExposureWindow, GOLD],
              ] as Array<[string, string, string]>).map(([k, v, c]) => (
                <div key={k} className="rounded-md border border-white/8 bg-white/[0.025] p-2.5">
                  <div className="text-sm font-bold" style={{ color: c }}>{v}</div>
                  <div className="text-[10px] uppercase tracking-wide text-white/45">{k}</div>
                </div>
              ))}
            </div>
          </Panel>
        </section>

        {/* Dependency Graph + Blockers */}
        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-3 xl:col-span-7">
            <div className="p-2">
              <SectionTitle suffix={<span className="text-[11px] text-white/40">{plan.dependencyGraph.nodes.length} nodes · {plan.dependencyGraph.edges.length} edges</span>}>Migration Dependency Graph</SectionTitle>
            </div>
            <DependencyGraph nodes={plan.dependencyGraph.nodes} edges={plan.dependencyGraph.edges} />
            <p className="px-2 pb-1 text-[11px] text-white/45">{plan.dependencyAnalysis.summary || 'No dependency telemetry yet.'}</p>
          </Panel>

          <Panel className="p-5 xl:col-span-5">
            <SectionTitle suffix={<Badge color={ORANGE}>{plan.blockers.filter((b) => b.id !== 'blk-none').length}</Badge>}>Migration Blockers</SectionTitle>
            <div className="space-y-2.5">
              {plan.blockers.map((b) => {
                const color = severityColor(b.severity);
                return (
                  <div key={b.id} className="rounded-md border border-white/8 bg-white/[0.025] p-3">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-bold text-white/85">{b.title}</span>
                      <span className="rounded px-1.5 py-0.5 text-[9px] font-black uppercase" style={{ color, backgroundColor: `${color}1a` }}>{b.severity}</span>
                    </div>
                    <div className="mt-1 text-[11px] text-white/50">{b.impact}</div>
                    <div className="mt-1 text-[11px]" style={{ color: EMERALD }}>{`→ ${b.resolution}`}</div>
                    {b.affectedAssets.length ? <div className="mt-1 truncate text-[10px] text-white/35">{b.affectedAssets.join(', ')}</div> : null}
                  </div>
                );
              })}
            </div>
          </Panel>
        </section>

        {/* Readiness Heatmap */}
        <Panel className="p-5">
          <SectionTitle
            suffix={
              <div className="flex flex-wrap gap-1.5">
                {['all', 'Ready', 'Needs Validation', 'Needs Upgrade', 'Blocked', 'Unknown'].map((f) => (
                  <button key={f} type="button" onClick={() => setHeatmapFilter(f)} className={`rounded border px-2 py-0.5 text-[10px] font-bold transition ${heatmapFilter === f ? 'border-blue-400/50 bg-blue-500/15 text-blue-200' : 'border-white/10 bg-black/20 text-white/50 hover:border-blue-400/35'}`}>{f === 'all' ? 'All' : f}</button>
                ))}
              </div>
            }
          >
            Readiness Heatmap
          </SectionTitle>
          <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-5">
            {heatmapStates.map((s) => (
              <button key={s.label} type="button" onClick={() => setHeatmapFilter(s.label)} className="rounded-md border border-white/8 bg-white/[0.025] p-3 text-left transition hover:border-blue-400/35">
                <div className="text-xl font-semibold" style={{ color: s.color }}>{integerFmt(s.value)}</div>
                <div className="text-[10px] uppercase tracking-wide text-white/45">{s.label}</div>
              </button>
            ))}
          </div>
          {filteredHeatmapRows.length ? (
            <div className="overflow-x-auto">
              <table className="min-w-[520px] w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.08em] text-white/35">
                    <th className="pb-2.5 font-black">Asset</th><th className="pb-2.5 font-black">Type</th><th className="pb-2.5 font-black">Environment</th><th className="pb-2.5 font-black">Risk</th><th className="pb-2.5 font-black">State</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredHeatmapRows.map((r, i) => {
                    const sc = r.state === 'Ready' ? EMERALD : r.state === 'Needs Validation' ? AMBER : r.state === 'Needs Upgrade' ? ORANGE : r.state === 'Blocked' ? RED : VIOLET;
                    return (
                      <tr key={`${r.asset}-${i}`} className="border-b border-white/5 text-white/70">
                        <td className="max-w-[200px] truncate py-2 font-medium text-white/82">{r.asset}</td>
                        <td className="py-2">{r.type}</td>
                        <td className="py-2">{r.environment}</td>
                        <td className="py-2 font-mono" style={{ color: riskTone(r.riskScore) }}>{integerFmt(r.riskScore)}</td>
                        <td className="py-2"><span className="rounded px-1.5 py-0.5 text-[10px] font-black" style={{ color: sc, backgroundColor: `${sc}1a` }}>{r.state}</span></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : <EmptyState label="No assets for this state." />}
        </Panel>

        {/* Timeline */}
        <Panel className="p-5">
          <SectionTitle suffix={<Clock className="h-4 w-4 text-white/40" />}>Migration Timeline</SectionTitle>
          <div className="space-y-2">
            {plan.timeline.map((phase) => (
              <div key={phase.phase} className="grid grid-cols-[140px_1fr_auto] items-center gap-3 rounded-md border border-white/8 bg-white/[0.025] p-3">
                <div>
                  <div className="text-xs font-bold text-white/85">{phase.phase}</div>
                  <div className="text-[10px] text-white/40">{phase.owner}</div>
                </div>
                <div>
                  <div className="h-2 overflow-hidden rounded-full bg-white/5">
                    <div className="h-full rounded-full" style={{ width: `${phase.completionPct}%`, backgroundColor: phase.completionPct >= 100 ? EMERALD : BLUE }} />
                  </div>
                  <div className="mt-1 flex items-center justify-between text-[10px] text-white/40">
                    <span>{phase.startDate} → {phase.endDate}</span>
                    <span>{percentLabel(phase.completionPct)} · {integerFmt(phase.durationWeeks)}w</span>
                  </div>
                </div>
                <span className="rounded px-2 py-0.5 text-[10px] font-black" style={{ color: levelTone(phase.riskLevel), backgroundColor: `${levelTone(phase.riskLevel)}1a` }}>{phase.riskLevel}</span>
              </div>
            ))}
          </div>
        </Panel>

        {/* Compliance + Cost Forecast */}
        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-7">
            <SectionTitle suffix={<ShieldCheck className="h-4 w-4 text-white/40" />}>Compliance Impact Center</SectionTitle>
            <div className="overflow-x-auto">
              <table className="min-w-[520px] w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-white/8 text-[9px] uppercase tracking-[0.08em] text-white/35">
                    <th className="pb-2.5 font-black">Framework</th><th className="pb-2.5 font-black">Control</th><th className="pb-2.5 font-black">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {plan.compliance.map((c) => {
                    const sc = c.status === 'aligned' ? GREEN : c.status === 'partial' ? GOLD : c.status === 'gap' ? RED : SLATEISH;
                    return (
                      <tr key={c.framework} className="border-b border-white/5 text-white/70">
                        <td className="py-2 font-medium text-white/82">{c.framework}</td>
                        <td className="max-w-[240px] truncate py-2">{c.control}</td>
                        <td className="py-2"><span className="rounded px-1.5 py-0.5 text-[10px] font-black uppercase" style={{ color: sc, backgroundColor: `${sc}1a` }}>{c.status}</span></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Panel>

          <Panel className="p-5 xl:col-span-5">
            <SectionTitle suffix={<Banknote className="h-4 w-4 text-white/40" />}>Cost Forecasting</SectionTitle>
            <BarList rows={plan.costForecast.lines.map((l) => ({ label: l.category, value: l.costUsd }))} colorFor={() => EMERALD} max={Math.max(1, ...plan.costForecast.lines.map((l) => l.costUsd))} />
            <div className="mt-3 grid grid-cols-2 gap-2">
              <div className="rounded-md border border-white/8 bg-black/20 p-3"><div className="text-lg font-semibold" style={{ color: EMERALD }}>{usd(plan.costForecast.totalUsd)}</div><div className="text-[10px] uppercase tracking-wide text-white/45">Total Migration Cost</div></div>
              <div className="rounded-md border border-white/8 bg-black/20 p-3"><div className="text-lg font-semibold" style={{ color: GREEN }}>{usd(plan.costForecast.projectedRiskReductionValueUsd)}</div><div className="text-[10px] uppercase tracking-wide text-white/45">Projected Risk-Reduction Value</div></div>
            </div>
          </Panel>
        </section>

        {/* Migration jobs + report exports */}
        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="p-5 xl:col-span-7">
            <SectionTitle suffix={<span className="text-[11px] text-white/40">{plan.migrationJobs.length} jobs</span>}>Migration Execution Jobs</SectionTitle>
            {plan.migrationJobs.length ? (
              <div className="space-y-2">
                {plan.migrationJobs.slice(0, 8).map((job) => {
                  const done = /completed|done/i.test(job.status);
                  const failed = /failed/i.test(job.status);
                  const color = failed ? RED : done ? EMERALD : GOLD;
                  return (
                    <div key={job.id} className="grid grid-cols-[1fr_120px_auto] items-center gap-3 rounded-md border border-white/8 bg-white/[0.025] p-2.5 text-xs">
                      <span className="truncate font-medium text-white/80">{job.jobType}</span>
                      <div className="h-1.5 overflow-hidden rounded-full bg-white/5"><div className="h-full rounded-full" style={{ width: `${job.progress}%`, backgroundColor: color }} /></div>
                      <span className="rounded px-1.5 py-0.5 text-[10px] font-black uppercase" style={{ color, backgroundColor: `${color}1a` }}>{job.status}</span>
                    </div>
                  );
                })}
              </div>
            ) : <EmptyState label="No migration jobs executing." hint="Jobs appear here once a migration plan is started." />}
          </Panel>

          <Panel className="p-5 xl:col-span-5">
            <SectionTitle>Executive Reporting</SectionTitle>
            <p className="mb-3 text-[11px] text-white/45">Generate board-ready deliverables from this migration plan via the Enterprise Reporting Engine™.</p>
            <div className="grid grid-cols-2 gap-2">
              {([
                ['Migration Report (PDF)', 'pdf', 'migration', FileText],
                ['Migration Report (DOCX)', 'docx', 'migration', FileText],
                ['Executive Report (PDF)', 'pdf', 'executive', Building2],
                ['Plan Data (JSON)', 'json', 'migration', Download],
              ] as Array<[string, 'pdf' | 'docx' | 'json', 'migration' | 'executive', LucideIcon]>).map(([label, fmt, kind, Icon]) => (
                <button key={label} type="button" disabled={exporting !== null || !plan.hasData} onClick={() => void generate(fmt, kind)} className="flex items-center gap-2 rounded-md border border-white/10 bg-white/[0.025] px-3 py-2.5 text-left text-xs font-bold text-white/75 transition hover:border-blue-400/40 hover:text-blue-200 disabled:opacity-50">
                  <Icon className="h-4 w-4 shrink-0 text-blue-300" />{label}
                </button>
              ))}
            </div>
            <button type="button" onClick={() => navigate('/dashboard/quantum-readiness/reports')} className="mt-3 inline-flex items-center gap-1 text-xs font-bold text-blue-300 transition hover:text-blue-200">
              Open Report Center <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </Panel>
        </section>

        {/* Footer */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-1 text-[11px] text-white/35">
          <span className="inline-flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${sseConnected ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.8)]' : 'bg-amber-300 animate-pulse'}`} />
            {sseConnected ? 'Live migration-plan stream & table subscriptions connected' : 'Connecting live migration stream'}
          </span>
          <span>{plan.evidence.note || `Last synchronized: ${longDate(plan.lastScanAt || plan.generatedAt)}`}</span>
        </div>
      </div>
    </div>
  );
}

function DependencyGraph({ nodes, edges }: { nodes: Array<{ id: string; label: string; type: string; riskScore: number; posture: string; internetFacing: boolean }>; edges: Array<{ source: string; target: string }> }) {
  const layout = useMemo(() => {
    const W = 820;
    const H = 420;
    const cx = W / 2;
    const cy = H / 2;
    const positions = new Map<string, { x: number; y: number }>();
    if (nodes.length === 1) {
      positions.set(nodes[0].id, { x: cx, y: cy });
    } else {
      nodes.forEach((n, i) => {
        const angle = (i / Math.max(1, nodes.length)) * Math.PI * 2;
        const radius = n.internetFacing ? 110 : 180;
        positions.set(n.id, { x: cx + Math.cos(angle) * radius, y: cy + Math.sin(angle) * radius });
      });
    }
    return { W, H, positions };
  }, [nodes]);

  if (!nodes.length) {
    return <div className="grid min-h-[300px] place-items-center text-xs text-white/38">No dependency telemetry yet. Discover assets and trust relationships to populate the graph.</div>;
  }

  return (
    <svg viewBox={`0 0 ${layout.W} ${layout.H}`} className="h-[360px] w-full" role="img" aria-label="Migration dependency graph">
      {edges.map((e, i) => {
        const a = layout.positions.get(e.source);
        const b = layout.positions.get(e.target);
        if (!a || !b) return null;
        return <line key={`${e.source}-${e.target}-${i}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="rgba(255,255,255,0.12)" strokeWidth={1} />;
      })}
      {nodes.map((n) => {
        const pos = layout.positions.get(n.id);
        if (!pos) return null;
        const color = POSTURE_COLOR[n.posture] || BLUE;
        const r = 9 + Math.min(12, n.riskScore / 8);
        return (
          <g key={n.id}>
            <circle cx={pos.x} cy={pos.y} r={r} fill={`${color}28`} stroke={color} strokeWidth={1.8} />
            {n.internetFacing ? <circle cx={pos.x + r * 0.7} cy={pos.y - r * 0.7} r={3} fill={ORANGE} /> : null}
            <text x={pos.x} y={pos.y + r + 13} textAnchor="middle" fill="rgba(255,255,255,0.72)" fontSize="11">{n.label.length > 22 ? `${n.label.slice(0, 22)}…` : n.label}</text>
            <text x={pos.x} y={pos.y + 4} textAnchor="middle" fill="#fff" fontSize="9" fontWeight="bold">{integerFmt(n.riskScore)}</text>
          </g>
        );
      })}
      <g transform="translate(16,16)">
        {([['Quantum-Vulnerable', RED], ['Hybrid', AMBER], ['PQC-Ready', EMERALD]] as Array<[string, string]>).map(([label, color], i) => (
          <g key={label} transform={`translate(0,${i * 18})`}>
            <circle cx={6} cy={6} r={5} fill={color} />
            <text x={18} y={10} fill="rgba(255,255,255,0.55)" fontSize="10">{label}</text>
          </g>
        ))}
      </g>
    </svg>
  );
}
