'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { CostAssumptionsEditor } from './CostAssumptionsEditor';
import { motion } from 'framer-motion';
import {
  Activity,
  ArrowRight,
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
  LockKeyhole,
  Radio,
  RefreshCw,
  Rocket,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Target,
  Workflow,
  SlidersHorizontal,
  type LucideIcon,
} from 'lucide-react';
import { useAuth } from '@/contexts/auth-context';
import { supabase } from '@/lib/supabase';
import { useMigrationPlan, type MigrationStrategy } from '@/hooks/use-migration-plan';
import { DEFAULT_ASSET_FILTERS, useMigrationAssets, type AssetAlgorithm, type AssetDossier, type AssetSummaryRecord, type QueueEntry } from '@/hooks/use-migration-assets';
import { AssetMigrationGuide, MigrationMonitoring, MigrationOverview, SCANNER_PATH, usePlannerExecution } from './_planner-guide';
import { labReadiness, type LabRun } from '@/lib/migration/sandbox-lab';
import { HANDOFF_REVIEW_FIELDS, isHeldMigrationWave, isVerifiedMigrationJob, parseHandoffReview, plannerStageAccess, type HandoffReview } from '@/lib/migration/planner-progress';
import './migration-planner.css';
import {
  AssetDossierSkeleton,
  AssetDossierView,
  AssetPortfolioOverview,
  AssetSelectorRail,
} from './_asset-workspace';
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
  assetIds: string[];
  scope: Array<HandoffAsset & { algorithms: AssetAlgorithm[]; preferredTarget: string | null }>;
  approval: { decision: string; decidedBy: string; decidedAt: string; reason: string } | null;
  executionPlanId?: string | null;
  executions?: { id: string; assetIds: string[]; ready: boolean; guided: boolean; handoffReview: (HandoffReview & { recordedBy: string; recordedAt: string }) | null }[];
  labEvidence?: Array<{ id: string; asset_id: string; attached_at: string }>;
}

const PLAN_STATUS_TONES: Record<string, string> = {
  approved: EMERALD,
  pending_approval: AMBER,
  rejected: RED,
};

function useApprovalPlans(token: string | undefined, ownerId: string | undefined, revision: string | null, proposalId: string | null) {
  const [result, setResult] = useState<{ ownerId?: string; plans: ApprovalPlan[]; error: string | null }>({ plans: [], error: null });
  const loadedRequest = useRef(0);

  const loadPlans = useCallback(async () => {
    if (!token) return;
    const requestId = ++loadedRequest.current;
    try {
      const query = new URLSearchParams({ proposals: '1' });
      if (proposalId) query.set('proposalId', proposalId);
      const response = await fetch(`/api/v1/migration-planner/plans?${query}`, { headers: { Authorization: `Bearer ${token}` } });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      if (requestId !== loadedRequest.current) return;
      setResult({ ownerId, plans: payload.data || [], error: null });
    } catch (err) {
      if (requestId === loadedRequest.current) setResult((current) => ({
        ownerId, plans: current.ownerId === ownerId ? current.plans : [],
        error: err instanceof Error ? err.message : 'Could not load approval records.',
      }));
    }
  }, [ownerId, token, proposalId]);

  useEffect(() => {
    void loadPlans();
    return () => { ++loadedRequest.current; };
  }, [loadPlans, revision]);
  useEffect(() => {
    if (!ownerId || !token) return;
    let timer: ReturnType<typeof setTimeout>;
    const channel = supabase.channel(`migration-proposal-updates-${ownerId}`)
      .on('postgres_changes', { event: '*', schema: 'public', table: 'migration_plans', filter: `user_id=eq.${ownerId}` }, () => {
        clearTimeout(timer);
        timer = setTimeout(() => void loadPlans(), 500);
      }).subscribe();
    return () => { clearTimeout(timer); void supabase.removeChannel(channel); };
  }, [ownerId, token, loadPlans]);

  return {
    plans: result.ownerId === ownerId ? result.plans : [],
    loadError: result.ownerId === ownerId ? result.error : null,
    loading: Boolean(token && result.ownerId !== ownerId),
    loadPlans,
  };
}

function ApprovalWorkflowPanel({ onDecision, queue, plans, loadPlans, onReviewExecution, canRemoveCancelled, busy: assetBusy }: {
  onDecision: (id: string) => void;
  queue: QueueEntry[];
  plans: ApprovalPlan[];
  loadPlans: () => Promise<void>;
  onReviewExecution: (proposal: ApprovalPlan) => void;
  canRemoveCancelled: (proposalId: string, assetId: string) => boolean;
  busy: string | null;
}) {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [rejectingId, setRejectingId] = useState<string | null>(null);
  const [reason, setReason] = useState('');
  const [name, setName] = useState('');
  const [targets, setTargets] = useState<Record<string, string>>({});
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [removing, setRemoving] = useState<{ planId: string; assetId: string; name: string } | null>(null);
  const availableQueue = queue.filter((asset) => !asset.reservation);
  const selectedQueue = availableQueue.filter((asset) => selectedIds.includes(asset.assetId));

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
        setRemoving(null);
        if (path === '/plans') setSelectedIds([]);
        await loadPlans();
        if (payload?.data?.id) onDecision(payload.data.id);
      } catch (err) {
        setMessage(err instanceof Error ? err.message : 'Action failed');
      } finally {
        setBusy(false);
      }
    },
    [token, loadPlans, onDecision],
  );

  const pending = plans.filter((p) => p.status === 'pending_approval');
  const approved = plans.filter((p) => p.status === 'approved');

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
      <p className="mb-3 text-sm text-[var(--mp-muted)]">Select queued assets to include in the proposal. Your queue order sets the order of the selected assets.</p>
      {message && <p role="status" className="mb-3 text-sm">{message}</p>}
      <form className="mb-4 space-y-3" onSubmit={(event) => {
        event.preventDefault();
        if (busy || assetBusy || !selectedQueue.length || selectedQueue.length > 50) return;
        const targetsForScope = Object.fromEntries(selectedQueue.map((entry) => [entry.assetId, entry.targets?.includes(targets[entry.assetId]) ? targets[entry.assetId] : '']));
        void post('/plans', { name, targets: targetsForScope, assetIds: selectedQueue.map((entry) => entry.assetId) }, 'Selected assets submitted for approval.');
      }}>
        <label className="block text-xs">Plan name <input className="mp-field mt-1" value={name} onChange={(event) => setName(event.target.value)} maxLength={160} placeholder="PQC migration plan (optional)" /></label>
        {queue.length > 0 && <fieldset className="space-y-1">
          <legend className="mb-1 text-sm font-semibold">Assets to submit ({selectedQueue.length} selected)</legend>
          {availableQueue.length > 1 && availableQueue.length <= 50 && <button type="button" className="mp-button" disabled={busy} onClick={() => setSelectedIds(selectedQueue.length === availableQueue.length ? [] : availableQueue.map((asset) => asset.assetId))}>{selectedQueue.length === availableQueue.length ? 'Clear selection' : 'Select all available'}</button>}
          <div className="max-h-56 overflow-y-auto">
            {queue.map((entry) => <label key={entry.assetId} className="flex min-h-11 items-center gap-2 text-sm">
              <input type="checkbox" checked={!entry.reservation && selectedIds.includes(entry.assetId)} disabled={busy || Boolean(entry.reservation)}
                onChange={(event) => setSelectedIds((ids) => event.target.checked ? [...ids, entry.assetId] : ids.filter((id) => id !== entry.assetId))} />
              <span className="break-words">{entry.name}</span>
              {entry.reservation && <span className="mp-muted">{entry.reservation === 'submitted' ? 'Already submitted' : 'In Live Migration Ops'}</span>}
            </label>)}
          </div>
        </fieldset>}
        {selectedQueue.some((entry) => entry.targets?.length) && <details className="mp-disclosure">
          <summary>Choose preferred planning targets</summary>
          <p className="mp-muted mt-2">These candidates describe the proposed change. Confirm what the agent or connector can apply before execution.</p>
          <div className="mt-2 grid gap-2 sm:grid-cols-2">
            {selectedQueue.filter((entry) => entry.targets?.length).map((entry) => <label key={entry.assetId} className="block min-w-0 break-words text-xs">
              {entry.name}
              <select className="mp-field mt-1" value={targets[entry.assetId] || ''} onChange={(event) => setTargets((current) => ({ ...current, [entry.assetId]: event.target.value }))}>
                <option value="">Leave for compatibility review</option>
                {entry.targets.map((target) => <option key={target} value={target}>{target}</option>)}
              </select>
            </label>)}
          </div>
        </details>}
        <button className="mp-button mp-button-primary" type="submit" disabled={busy || Boolean(assetBusy) || !user || !selectedQueue.length || selectedQueue.length > 50}>
          <ScrollText size={16} aria-hidden="true" /> {busy ? 'Working…' : 'Submit selected assets for approval'}
        </button>
        {selectedQueue.length > 50 && <p className="w-full text-xs text-[var(--mp-risk)]">Select up to 50 assets.</p>}
      </form>
      {plans.length ? (
        <div className="space-y-2">
          {plans.map((plan) => {
            const tone = PLAN_STATUS_TONES[plan.status.toLowerCase()] || SLATEISH;
            const canDispatch = plan.status === 'approved' && plan.approval?.decision === 'approve' && plan.scope.length > 0;
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
                  {plan.status === 'pending_approval' ? (
                    <div className="flex shrink-0 items-center gap-2">
                      <button className="mp-button" disabled={busy || !plan.scope.length} onClick={() => void post(`/plans/${encodeURIComponent(plan.id)}/approval`, { decision: 'approve' }, 'Approval recorded. Open Execution & validation to review the handoff.')}>Approve proposal</button>
                      <button className="mp-button" disabled={busy} onClick={() => setRejectingId(rejectingId === plan.id ? null : plan.id)}>Reject</button>
                    </div>
                  ) : null}
                  {canDispatch && <button className="mp-button" disabled={Boolean(assetBusy)} onClick={() => onReviewExecution(plan)}>{plan.executionPlanId ? 'Track execution' : 'Continue to execution'}</button>}
                </div>
                {plan.scope.length > 0 && (
                  <details className="mp-disclosure mt-2">
                    <summary>{plan.scope.length} assets in approved or proposed scope</summary>
                    <ul className="space-y-2 px-2 py-2 text-xs">
                      {plan.scope.map((asset, index) => {
                        const batch = plan.executions?.find((execution) => execution.assetIds.includes(asset.id));
                        return <li key={asset.id} className="break-words"><strong>{index + 1}. {asset.name}</strong> · {asset.priority} · {asset.owner}
                        {asset.preferredTarget && <p>Preferred target · {asset.preferredTarget}</p>}
                        {asset.algorithms.filter((algorithm) => algorithm.classification === 'vulnerable').map((algorithm) => <p key={`${algorithm.algorithm}:${algorithm.category}`} className="mp-muted">{algorithm.algorithm} → {algorithm.target}</p>)}
                        {plan.status === 'pending_approval' && <Link className="mp-button mt-1" to={`/dashboard/migration-sandbox?asset=${encodeURIComponent(asset.id)}`}>Test {asset.name} in Sandbox</Link>}
                        {batch?.ready && <Link className="mp-button mt-1" to={`/dashboard/live-migration?${new URLSearchParams({ planId: batch.id, proposal: plan.id })}`}>Open in Live Migration Ops</Link>}
                        {(!batch || canRemoveCancelled(plan.id, asset.id)) && ['approved', 'pending_approval'].includes(plan.status) && <button type="button" className="mp-button mt-1" disabled={busy} onClick={() => setRemoving({ planId: plan.id, assetId: asset.id, name: asset.name })}>Remove from proposal</button>}
                        </li>;
                      })}
                    </ul>
                  </details>
                )}
                {removing?.planId === plan.id && <div className="mp-actions mt-2" role="group" aria-label="Confirm removal from proposal">
                  <p className="w-full text-sm">Remove {removing.name} from this proposal?</p>
                  <button type="button" className="mp-button" disabled={busy} onClick={() => setRemoving(null)}>Keep asset</button>
                  <button type="button" className="mp-button" disabled={busy} onClick={() => void post(`/plans/${encodeURIComponent(plan.id)}/remove-assets`, { assetIds: [removing.assetId] }, 'Asset removed from the proposal.')}>Confirm removal</button>
                </div>}
                {Boolean(plan.labEvidence?.length) && <div className="mt-2 flex flex-wrap gap-2">
                  {plan.labEvidence?.map((run) => <Link key={run.id} className="mp-button" to={`/dashboard/migration-sandbox?asset=${encodeURIComponent(run.asset_id || plan.assetIds[0] || '')}&runId=${encodeURIComponent(run.id)}`}>Sandbox evidence · {longDate(run.attached_at)}</Link>)}
                </div>}
                {rejectingId === plan.id ? (
                  <div className="mt-2 flex flex-wrap items-center gap-2">
                    <input
                      value={reason}
                      aria-label="Rejection reason"
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
        <EmptyState label="No migration plans submitted yet." hint="Queue assets from Findings, then submit the scope when it is ready for review." />
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

const VIEWS = [
  { id: 'findings', label: 'Findings', icon: ShieldAlert },
  { id: 'planning', label: 'Plan & approve', icon: Layers },
  { id: 'execution', label: 'Execution & validation', icon: Activity },
  { id: 'analytics', label: 'Program analytics', icon: Gauge },
] as const;
type PlannerView = (typeof VIEWS)[number]['id'];
type HandoffAsset = Pick<AssetSummaryRecord, 'id' | 'name' | 'type' | 'environment' | 'owner' | 'riskScore' | 'priority'>;
const EMPTY_REVIEW: HandoffReview = { compatibilityEvidence: '', changeWindow: '', rollbackReference: '' };

function SandboxReview({ runId, assetId, token }: { runId: string; assetId: string | null; token?: string }) {
  const [run, setRun] = useState<LabRun | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    void fetch(`/api/v1/sandbox/lab/runs/${encodeURIComponent(runId)}`, { headers: { Authorization: `Bearer ${token}` }, signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error('The sandbox evidence could not be retrieved.');
        const payload = await response.json();
        const result = payload.data as LabRun;
        if (assetId && result.asset_id !== assetId) throw new Error('The sandbox evidence belongs to a different asset.');
        setRun(result);
      }).catch((err) => { if (!controller.signal.aborted) setError(err.message); });
    return () => controller.abort();
  }, [runId, assetId, token]);
  if (error) return <div className="mp-card mp-intro" role="alert">{error}</div>;
  if (!run) return <div className="mp-card mp-intro" role="status">Loading sandbox evidence…</div>;
  const readiness = labReadiness(run);
  return <section className="mp-card mp-intro">
    <h2>Sandbox evidence for {run.asset_snapshot.name}</h2>
    <p><strong>{readiness.label}</strong> · {readiness.reason}</p>
    <Link className="mp-button" to={`/dashboard/migration-sandbox?asset=${encodeURIComponent(run.asset_snapshot.id)}&runId=${encodeURIComponent(run.id)}`}>Review checks and attach to a proposal</Link>
  </section>;
}

export default function MigrationPlanner() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const { session } = useAuth();
  const { plan, error, sseConnected, transport, lastVerifiedAt, refresh } = useMigrationPlan();
  const requestedView = VIEWS.find((item) => item.id === params.get('view'))?.id ?? 'findings';
  const requestedAsset = params.get('asset');
  const requestedProposal = params.get('proposal');
  const requestedExecution = params.get('executionPlan');
  const labRun = params.get('labRun');
  const [refreshing, setRefreshing] = useState(false);
  const [evidenceExporting, setEvidenceExporting] = useState(false);
  const [dispatch, setDispatch] = useState<ApprovalPlan | null>(null);
  const [handoffIds, setHandoffIds] = useState<string[]>([]);
  const [retryBatchId, setRetryBatchId] = useState<string | null>(null);
  const [handoffReview, setHandoffReview] = useState<HandoffReview>(EMPTY_REVIEW);
  const [dispatchError, setDispatchError] = useState<string | null>(null);
  const [releasingWave, setReleasingWave] = useState(false);
  const dispatchDialog = useRef<HTMLDialogElement>(null);
  const dossierTarget = useRef<HTMLDivElement>(null);
  const focusDossier = useRef(false);
  // Cost/value assumptions drive every currency figure on this page; editing
  // them must re-derive the plan, not just the dialog.
  const [assumptionsOpen, setAssumptionsOpen] = useState(false);
  const [strategyKey, setStrategyKey] = useState('balanced');
  const [exporting, setExporting] = useState<string | null>(null);
  const [heatmapFilter, setHeatmapFilter] = useState<string>('all');
  const [notice, setNotice] = useState<string | null>(null);
  // Roadmap handed off from the AI Migration Advisor™ (localStorage payload —
  // the exact waves/prioritization/rollback plan the advisor displayed).
  const [handoff, setHandoff] = useState<MigrationHandoff | null>(() => readMigrationHandoff(session?.user?.id));

  const dismissHandoff = useCallback(() => {
    clearMigrationHandoff(session?.user?.id);
    setHandoff(null);
  }, [session?.user?.id]);

  /* ---- Asset-centric migration workspace ---- */
  const assetWorkspace = useMigrationAssets(lastVerifiedAt);
  const {
    portfolio,
    portfolioLoading,
    filters,
    setFilters,
    selectedId,
    selectAsset: loadAsset,
    dossier,
    position,
    dossierLoading,
    changedFields,
    queue,
    enqueue,
    dequeue,
    reorderQueue,
    applyRecommendedOrder,
    sendToLiveMigration,
    error: assetError,
    portfolioError,
    dossierError,
    queueError,
    busy: assetBusy,
  } = assetWorkspace;
  const refreshAssets = assetWorkspace.refresh;
  const { plans, loadError: approvalError, loading: proposalsLoading, loadPlans } = useApprovalPlans(session?.access_token, session?.user.id, lastVerifiedAt, requestedProposal);
  const proposals = plans.filter((item) => item.scope.length > 0 && ['approved', 'pending_approval', 'rejected'].includes(item.status));
  const proposal = requestedProposal ? proposals.find((item) => item.id === requestedProposal)
    : proposals.find((item) => !requestedAsset || item.assetIds.includes(requestedAsset));
  const approved = proposal?.status === 'approved' && proposal.approval?.decision === 'approve';
  const batches = approved ? proposal.executions || [] : [];
  const readyBatches = batches.filter((batch) => batch.ready);
  const batch = readyBatches.find((item) => item.id === requestedExecution) ?? readyBatches[0];
  const executionPlanId = batch?.id ?? null;
  const execution = usePlannerExecution(approved ? proposal.id : null);
  const sentIds = new Set(batches.flatMap((item) => item.assetIds));
  const latestDispatch = dispatch ? proposals.find((item) => item.id === dispatch.id && item.status === 'approved') : undefined;
  const dispatchOptions = latestDispatch?.scope.filter((asset) => {
    const executionBatch = latestDispatch.executions?.find((item) => item.assetIds.includes(asset.id));
    return retryBatchId ? executionBatch?.id === retryBatchId && !executionBatch.ready : !executionBatch;
  }) || [];
  const selectedHandoffIds = dispatchOptions.filter((asset) => handoffIds.includes(asset.id)).map((asset) => asset.id);
  const scopeIds = new Set(proposal?.assetIds);
  const jobsByAsset = new Map<string, (typeof execution.data.jobs)[number]>();
  for (const job of execution.data.jobs) {
    if (job.isSandbox || !job.assetId || !scopeIds.has(job.assetId)) continue;
    const existing = jobsByAsset.get(job.assetId);
    if (!existing || job.updatedAt > existing.updatedAt) jobsByAsset.set(job.assetId, job);
  }
  const verifiedIds = new Set([...jobsByAsset].filter(([, job]) => isVerifiedMigrationJob(job)).map(([id]) => id));
  const executionVerified = Boolean(executionPlanId && execution.state === 'success' && !execution.error && scopeIds.size && verifiedIds.size === scopeIds.size);
  const access = plannerStageAccess({ queued: queue.entries.length > 0, proposed: Boolean(proposal), approved, verified: executionVerified });
  const view = access[requestedView] ? requestedView : access.execution ? 'execution' : access.planning ? 'planning' : 'findings';
  const queuedIds = new Set(queue.entries.map((entry) => entry.assetId));
  const reviewedAsset = dossier ? { ...dossier, queued: queuedIds.has(dossier.id) } : null;
  const nextWave = batch?.guided && execution.state === 'success' && !execution.error
    ? proposal?.scope.find((asset) => batch.assetIds.includes(asset.id) && !verifiedIds.has(asset.id)) : null;
  const nextWaveJob = nextWave ? jobsByAsset.get(nextWave.id) : null;
  const canReleaseWave = Boolean(nextWaveJob?.rawStatus === 'pending' && isHeldMigrationWave(nextWaveJob));
  const checkingProgress = proposalsLoading || (!queue.planId && !queueError) || Boolean(executionPlanId && execution.state === 'loading');

  useEffect(() => { loadAsset(requestedAsset); }, [loadAsset, requestedAsset]);
  useEffect(() => {
    if (!focusDossier.current || view !== 'findings' || !dossier || dossier.id !== requestedAsset) return;
    const frame = requestAnimationFrame(() => {
      dossierTarget.current?.focus();
      focusDossier.current = false;
    });
    return () => cancelAnimationFrame(frame);
  }, [dossier, requestedAsset, view]);
  useEffect(() => {
    if (dispatch && dispatchDialog.current && !dispatchDialog.current.open) dispatchDialog.current.showModal();
  }, [dispatch]);

  const goTo = (nextView: PlannerView) => setParams((current) => {
    if (!access[nextView]) return current;
    const next = new URLSearchParams(current);
    next.set('view', nextView);
    return next;
  });
  const selectAsset = (id: string | null) => {
    focusDossier.current = Boolean(id && (id !== requestedAsset || view !== 'findings'));
    setParams((current) => {
      const next = new URLSearchParams(current);
      if (id) next.set('asset', id);
      else next.delete('asset');
      if (id !== requestedAsset) {
        next.delete('proposal');
        next.delete('executionPlan');
        next.delete('labRun');
      }
      next.set('view', 'findings');
      return next;
    });
  };

  const selectProposal = (id: string, nextView: PlannerView = 'planning') => setParams((current) => {
    const next = new URLSearchParams(current);
    if (current.get('proposal') !== id) next.delete('executionPlan');
    if (id) next.set('proposal', id);
    else next.delete('proposal');
    next.set('view', nextView);
    return next;
  });

  const toggleQueue = (id: string) => void (queuedIds.has(id) ? dequeue(id) : enqueue([id]));

  const refreshPlanner = useCallback(async () => {
    setRefreshing(true);
    try { await Promise.all([refresh(), refreshAssets(), loadPlans()]); }
    finally { setRefreshing(false); }
  }, [refresh, refreshAssets, loadPlans]);

  const openHandoff = (item: ApprovalPlan, retry?: NonNullable<ApprovalPlan['executions']>[number]) => {
    setHandoffIds(retry?.assetIds ?? []);
    setRetryBatchId(retry?.id ?? null);
    setDispatch(item);
  };

  const executeHandoff = async () => {
    if (!dispatch || assetBusy || approvalError || !selectedHandoffIds.length) return;
    const review = parseHandoffReview(handoffReview);
    if (!review) return;
    setDispatchError(null);
    try {
      const result = await sendToLiveMigration(dispatch.id, selectedHandoffIds, review);
      dispatchDialog.current?.close();
      navigate(`/dashboard/live-migration?${new URLSearchParams({ planId: result.planId, proposal: dispatch.id })}`);
    } catch (err) {
      setDispatchError(err instanceof Error ? err.message : 'Could not send the migration.');
      void loadPlans();
    }
  };

  const releaseWave = async () => {
    const token = session?.access_token;
    if (!token || !executionPlanId || !canReleaseWave || releasingWave) return;
    setReleasingWave(true);
    setNotice(null);
    try {
      const response = await fetch(`/api/v1/migration/plans/${encodeURIComponent(executionPlanId)}/action`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ action: 'approve_next_phase' }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || 'Could not release the next wave.');
      setNotice(`${nextWave?.name || 'Next wave'} released to Live Migration Ops.`);
      await execution.refresh({ force: true });
    } catch (err) {
      setNotice(err instanceof Error ? err.message : 'Could not release the next wave.');
    } finally { setReleasingWave(false); }
  };

  const openSandbox = (asset: AssetDossier) => navigate(`/dashboard/migration-sandbox?asset=${encodeURIComponent(asset.id)}`);

  const exportAssetEvidence = async (asset: AssetDossier) => {
    const token = session?.access_token;
    if (!token) return;
    setEvidenceExporting(true);
    setNotice(null);
    try {
      const response = await fetch(`/api/v1/migration-planner/plans?assetId=${encodeURIComponent(asset.id)}`, { headers: { Authorization: `Bearer ${token}` } });
      if (!response.ok) throw new Error(`Could not load approval evidence (HTTP ${response.status}).`);
      const payload = await response.json();
      const verified = asset.migrationStatus === 'Completed' && asset.validation.validated && asset.posture === 'pqc' && !asset.vulnerableComponentCount;
      const blob = new Blob([JSON.stringify({ exportedAt: new Date().toISOString(), asset, plans: payload.data, verified }, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `migration-evidence-${asset.id}.json`;
      link.click();
      URL.revokeObjectURL(url);
      setNotice('Asset evidence exported.');
    } catch (err) {
      setNotice(err instanceof Error ? err.message : 'Could not export asset evidence.');
    } finally {
      setEvidenceExporting(false);
    }
  };

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
        const response = await fetch('/api/v1/reports/generate', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ format, kind }),
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error?.message || 'Report generation failed');
        const [{ exportReadinessReport }, { downloadDocument }, { evidenceAssessmentReportSchema }] = await Promise.all([
          import('@/services/reporting/ReadinessDocument'),
          import('@/services/reporting/exporters/DocumentExporters'),
          import('@/services/reporting/schemas/ReportSchema'),
        ]);
        const result = await exportReadinessReport(evidenceAssessmentReportSchema.parse(payload.data), format);
        downloadDocument(result);
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
    <div className="mp-page">
      <div className="mp-container">
        <header className="mp-card mp-header">
          <div className="mp-heading-row">
            <div>
              <h1>Migration Planner</h1>
              <p>Review vulnerable cryptography, prepare a staged rollout, and verify the change with fresh evidence.</p>
            </div>
            <div className="mp-actions">
              <button className="mp-button" onClick={() => void refreshPlanner()} disabled={refreshing}><RefreshCw size={16} aria-hidden="true" /> {refreshing ? 'Refreshing…' : 'Refresh'}</button>
              <Link className="mp-button" to={plan.advisor.deepLink}><BrainCircuit size={16} aria-hidden="true" /> AI Advisor</Link>
              <button className="mp-button mp-button-primary" onClick={() => void generate('pdf', 'migration')} disabled={exporting !== null || !plan.hasData}><FileText size={16} aria-hidden="true" /> {exporting === 'migration-pdf' ? 'Generating…' : 'Migration report'}</button>
            </div>
          </div>
          <div className="mp-freshness">
            <span className={`mp-chip ${sseConnected && !error ? 'mp-live' : ''}`} role="status"><Radio size={14} aria-hidden="true" />{sseConnected && !error ? 'Live updates' : transport === 'polling' || lastVerifiedAt ? 'Reconnecting' : 'Connecting to live updates'}</span>
            {portfolio.generatedAt && <span className="mp-muted">Asset data checked {longDate(portfolio.generatedAt)}</span>}
            {plan.lastScanAt && <span className="mp-muted">Latest assessment {longDate(plan.lastScanAt)}</span>}
          </div>
        </header>

        {error && <div role="alert" className="mp-card mp-intro text-sm text-[var(--mp-risk)]">Program data could not refresh. {error}</div>}
        {portfolioError && <div role="alert" className="mp-card mp-intro text-sm text-[var(--mp-risk)]">Asset data could not refresh. {portfolioError}</div>}
        {assetError && <div role="alert" className="mp-card mp-intro text-sm text-[var(--mp-risk)]">{assetError}</div>}
        {notice && <div role="status" className="mp-card mp-intro text-sm">{notice}</div>}
        {labRun && <SandboxReview key={`${labRun}:${requestedAsset}`} runId={labRun} assetId={requestedAsset} token={session?.access_token} />}
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
        <section className="mp-card mp-intro" aria-labelledby="mp-progress-title">
          <div className="mp-heading-row">
            <div><h2 id="mp-progress-title">Migration progress</h2><p>Choose the assets and order, record approval, then verify each wave before moving forward.</p></div>
            {proposals.length > 0 && <label className="block min-w-0 text-xs">
              Proposal to track
              <select className="mp-field mt-1" value={proposal?.id ?? ''} onChange={(event) => selectProposal(event.target.value)}>
                <option value="" disabled>Choose a migration proposal</option>
                {proposals.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.status.replaceAll('_', ' ')}</option>)}
              </select>
            </label>}
          </div>
          {approvalError && <p role="alert">{approvalError} <button type="button" className="mp-button" onClick={() => void loadPlans()}>Retry</button></p>}
          <nav className="mp-stage-nav" aria-label="Migration workflow steps">
            {VIEWS.map(({ id, label, icon: Icon }, index) => {
              const status = {
                findings: access.planning ? 'Assets selected' : 'Queue assessed assets',
                planning: approved ? 'Approval recorded' : proposal?.status === 'pending_approval' ? 'Awaiting approval' : 'Submit and approve a proposal',
                execution: executionVerified ? 'Validation passed' : executionPlanId ? `${verifiedIds.size} of ${scopeIds.size} assets verified` : 'Send the approved proposal',
                analytics: access.analytics ? 'Available' : 'Requires passing validation',
              }[id];
              return <button key={id} type="button" aria-current={view === id ? 'step' : undefined} disabled={!access[id]} onClick={() => goTo(id)}>
                <Icon size={17} aria-hidden="true" />
                <span><strong>{index + 1}. {label}</strong><small>{status}</small></span>
                {!access[id] && <LockKeyhole size={14} aria-label="Locked" />}
              </button>;
            })}
          </nav>
          {view !== requestedView && <p role="status">{checkingProgress ? 'Checking saved migration progress…' : `Finish the required earlier steps to open ${VIEWS.find((item) => item.id === requestedView)?.label}.`}</p>}
          {view === 'findings' && queue.entries.length > 0 && <button type="button" className="mp-button mp-button-primary mt-3" onClick={() => goTo('planning')}>Review migration queue ({queue.entries.length}) <ArrowRight size={16} aria-hidden="true" /></button>}
        </section>

        {view === 'findings' && <MigrationOverview summary={portfolio.generatedAt ? portfolio.summary : null} readiness={plan.hasData ? plan.hero.readinessScore : null} loading={portfolioLoading} />}

        {(view === 'findings' || view === 'planning') && (
          <section className="mp-workspace" aria-label={view === 'findings' ? 'Asset findings and migration guidance' : 'Queue and approval workspace'}>
            <AssetSelectorRail
              tab={view === 'findings' ? 'assets' : 'queue'}
              assets={portfolio.assets}
              total={portfolio.total}
              totalUnfiltered={portfolio.totalUnfiltered}
              summary={portfolio.summary}
              environments={portfolio.environments}
              filters={filters}
              setFilters={setFilters}
              selectedId={selectedId}
              onSelect={selectAsset}
              onQueue={toggleQueue}
              loading={portfolioLoading}
              queue={queue.entries}
              onDequeue={(id) => void dequeue(id)}
              onReorder={(ids) => void reorderQueue(ids)}
              onApplyRecommended={() => void applyRecommendedOrder()}
              busy={assetBusy}
              page={assetWorkspace.page}
              pageSize={assetWorkspace.pageSize}
              onPage={assetWorkspace.setPage}
              loadError={view === 'findings' ? portfolioError : queueError}
              onResetFilters={() => setFilters(DEFAULT_ASSET_FILTERS)}
            />

            <div className="mp-workspace-body">
              {view === 'planning' ? (
                <>
                  <section className="mp-card mp-intro">
                    <h2>Build a migration plan</h2>
                    <p>Use <strong>Make first</strong> or the arrows to set the rollout order. Review the asset scope, target candidates and sandbox results before approving the proposal.</p>
                    <div className="mp-actions">
                      <button className="mp-button" onClick={() => goTo('findings')}>Review findings <ArrowRight size={16} aria-hidden="true" /></button>
                      <Link className="mp-button" to={requestedAsset ? `/dashboard/migration-sandbox?asset=${encodeURIComponent(requestedAsset)}` : '/dashboard/migration-sandbox'}>Open Migration Sandbox</Link>
                    </div>
                    {queueError && <p role="alert">{queueError}</p>}
                  </section>
                  <ApprovalWorkflowPanel queue={queue.entries} plans={proposals} loadPlans={loadPlans} onDecision={(id) => { selectProposal(id); void refresh(); void refreshAssets(); }}
                    onReviewExecution={(item) => selectProposal(item.id, 'execution')}
                    canRemoveCancelled={(id, assetId) => id === proposal?.id && execution.state === 'success' && !execution.error && jobsByAsset.get(assetId)?.status === 'cancelled'} busy={assetBusy} />
                </>
              ) : requestedAsset ? (
                <div ref={dossierTarget} tabIndex={-1} className="min-w-0">
                  {dossierError && <div role="alert" className="mp-card mp-intro mb-3">
                    <h2>Could not load this asset</h2><p>{dossierError}</p>
                    <div className="mp-actions"><button className="mp-button" onClick={() => loadAsset(requestedAsset)}>Retry</button><button className="mp-button" onClick={() => selectAsset(null)}>Back to findings</button></div>
                  </div>}
                  {reviewedAsset?.id === requestedAsset ? (
                    <AssetDossierView asset={reviewedAsset} position={position} loading={dossierLoading} changedFields={changedFields}
                      onQueue={() => toggleQueue(reviewedAsset.id)} onReviewQueue={() => goTo('planning')} onClear={() => selectAsset(null)} busy={assetBusy}>
                      <AssetMigrationGuide key={reviewedAsset.id} asset={reviewedAsset} busy={Boolean(assetBusy) || evidenceExporting}
                        onPlan={() => reviewedAsset.queued ? goTo('planning') : toggleQueue(reviewedAsset.id)}
                        onSandbox={() => void openSandbox(reviewedAsset)}
                        onReport={() => void exportAssetEvidence(reviewedAsset)} />
                    </AssetDossierView>
                  ) : !dossierError ? <AssetDossierSkeleton /> : null}
                </div>
              ) : (
                <>
                  <section className="mp-card mp-intro">
                    <h2>{portfolio.generatedAt && !portfolio.totalUnfiltered ? 'Discover your first assets' : 'Choose the assets to migrate'}</h2>
                    <p>{portfolio.generatedAt && !portfolio.totalUnfiltered ? 'Run a PQC discovery scan or connect an asset source. Detected algorithms and findings appear here when evidence is available.' : 'Search or filter the findings to review any asset. Use Queue to include it and Unqueue to remove it from the next proposal.'}</p>
                    <div className="mp-actions">
                      <Link className="mp-button" to={SCANNER_PATH}>Open PQC Scanner</Link>
                      {portfolio.summary.vulnerableAssets > 0 && <button className="mp-button" onClick={() => setFilters({ ...DEFAULT_ASSET_FILTERS, posture: 'needs-migration' })}>Filter to vulnerable assets</button>}
                    </div>
                  </section>
                  {portfolio.generatedAt && portfolio.totalUnfiltered > 0 && <details className="mp-disclosure">
                    <summary>Recommended order and portfolio evidence</summary>
                    <div className="mt-2"><AssetPortfolioOverview summary={portfolio.summary} recommendedOrder={portfolio.recommendedOrder} reconciliation={portfolio.reconciliation} onSelect={selectAsset} onQueue={toggleQueue} queuedIds={queuedIds} busy={Boolean(assetBusy)} /></div>
                  </details>}
                </>
              )}
            </div>
          </section>
        )}

        {view === 'execution' && proposal && <>
          <section className="mp-card mp-intro">
            <h2>{proposal.name}</h2>
            <p>Approved by {proposal.approval?.decidedBy} · {longDate(proposal.approval?.decidedAt || '')}</p>
            <p>Only the assets you select are sent to Live Migration Ops. Each handoff preserves their approved order.</p>
            <div className="mp-actions mb-3">
              {proposal.scope.some((asset) => !sentIds.has(asset.id)) && <button type="button" className="mp-button mp-button-primary" disabled={Boolean(assetBusy) || Boolean(approvalError)} onClick={() => openHandoff(proposal)}><Rocket size={16} aria-hidden="true" /> Select assets to send</button>}
              {batches.filter((item) => !item.ready).map((item) => <button key={item.id} type="button" className="mp-button" disabled={Boolean(assetBusy)} onClick={() => openHandoff(proposal, item)}>Retry incomplete handoff ({item.assetIds.length} assets)</button>)}
            </div>
            {readyBatches.length > 1 && <label className="mb-3 block text-sm">Handoff to manage
              <select className="mp-field mt-1" value={executionPlanId ?? ''} onChange={(event) => setParams((current) => {
                const next = new URLSearchParams(current); next.set('executionPlan', event.target.value); return next;
              })}>
                {readyBatches.map((item) => <option key={item.id} value={item.id}>{proposal.scope.filter((asset) => item.assetIds.includes(asset.id)).map((asset) => asset.name).join(', ')}</option>)}
              </select>
            </label>}
            {executionPlanId && <>
              <p role="status">{verifiedIds.size} of {scopeIds.size} assets have verified execution. {executionVerified ? 'Program Analytics is available.' : 'Each asset needs a completed operation and passing validation.'}</p>
              {batch?.handoffReview && <details className="mp-disclosure mb-3">
                <summary>Recorded handoff requirements</summary>
                <p className="mp-muted mt-2">Recorded by {batch.handoffReview.recordedBy} · {longDate(batch.handoffReview.recordedAt)}</p>
                <dl className="mt-2 space-y-2 text-sm">
                  {HANDOFF_REVIEW_FIELDS.map(({ key, label }) => <div key={key}><dt className="font-semibold">{label}</dt><dd className="mp-muted break-words">{batch.handoffReview?.[key]}</dd></div>)}
                </dl>
              </details>}
              <ol>
                {proposal.scope.map((asset, index) => {
                  const job = jobsByAsset.get(asset.id);
                  const status = verifiedIds.has(asset.id) ? 'Verified' : !job ? sentIds.has(asset.id) ? 'Awaiting operation evidence' : 'Ready to select' : job.rawStatus === 'pending' && isHeldMigrationWave(job) ? 'Waiting for release' : job.status.replaceAll('_', ' ');
                  return <li key={asset.id}><strong>{index + 1}. {asset.name}</strong><span className="mp-muted">{status}</span></li>;
                })}
              </ol>
              {canReleaseWave && <button type="button" className="mp-button mp-button-primary mt-3" disabled={releasingWave} onClick={() => void releaseWave()}>{releasingWave ? 'Releasing wave…' : `Release next wave · ${nextWave?.name}`}</button>}
              {nextWave && !canReleaseWave && <p>Finish execution and review validation for <strong>{nextWave.name}</strong> in Live Migration Ops.</p>}
              {executionVerified && <button type="button" className="mp-button mp-button-primary mt-3" onClick={() => goTo('analytics')}>Open Program Analytics <ArrowRight size={16} aria-hidden="true" /></button>}
            </>}
          </section>
          {executionPlanId && <MigrationMonitoring execution={execution} planId={executionPlanId} proposalId={proposal.id} />}
        </>}

        {view === 'analytics' && <div className="grid min-w-0 gap-4">
        <section className="mp-card mp-intro"><h2>{proposal?.name} is verified</h2><p>Passing execution and validation are recorded for all {scopeIds.size} scoped assets. The program metrics below cover the workspace.</p></section>
        <WorkflowRail activeStage="planning" />
        {/* 9-stage workflow */}
        <Panel className="p-5">
          <SectionTitle suffix={<span className="hidden text-[11px] text-white/40 lg:inline">Discover → Analyze → Prioritize → Simulate → Plan → Approve → Execute → Validate → Optimize</span>}>Migration Workflow</SectionTitle>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-9">
            {plan.stages.map((stage, index) => {
              const Icon = STAGE_ICONS[stage.key] || Workflow;
              const tone = stage.status === 'Complete' ? EMERALD : stage.status === 'In Progress' ? GOLD : stage.status === 'Ready' ? CYAN : SLATEISH;
              return (
                <div key={stage.key} title={stage.evidence} className="rounded-lg border border-white/8 bg-white/[0.025] p-3">
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
                    <span style={{ color: stage.status === 'Pending' ? undefined : tone }}>{stage.status}</span>
                    <span>{compactFmt(stage.assetCount)}</span>
                  </div>
                  {/* The record the status was decided from, so no stage is a bare label. */}
                  <p className="mt-1.5 line-clamp-2 text-[9px] leading-snug text-white/35">{stage.evidence}</p>
                </div>
              );
            })}
          </div>
        </Panel>

        <CostAssumptionsEditor
          open={assumptionsOpen}
          onClose={() => setAssumptionsOpen(false)}
          onSaved={() => void refresh()}
        />

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
            { label: 'Critical Findings Remaining', value: integerFmt(plan.hero.criticalFindingsRemaining), detail: 'Highest priority', color: ORANGE, icon: ShieldAlert },
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
                  {w.coverage ? <div className="mt-0.5 text-[10px] text-white/40">{w.coverage}</div> : null}
                  <div className="mt-2 flex flex-wrap gap-3 text-[11px]">
                    <span style={{ color: GREEN }}>Risk ↓ {percentLabel(w.riskReductionPct)}</span>
                    <span className="text-white/55">{usd(w.costUsd)}</span>
                    <span className="text-white/55">{w.timelineLabel}</span>
                    <span style={{ color: CYAN }}>Compliance +{percentLabel(w.complianceIncreasePct)}</span>
                  </div>
                </div>
              ))}
            </div>
            {/* Scenarios overlap by construction; adding them would double-count. */}
            <p className="mt-2.5 text-[9.5px] leading-relaxed text-white/35">
              Alternatives sized from measured component scope — compare them, do not add them. Cost and timeline scale
              with the share of the {plan.hero.vulnerableComponents} vulnerable component(s) each one covers.
            </p>
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
                ['Overall', plan.sharedResponsibility.readiness.overall, GOLD],
                ['Customer', plan.sharedResponsibility.readiness.customer, CYAN],
                ['Provider', plan.sharedResponsibility.readiness.provider, BLUE],
                ['Ecosystem', plan.sharedResponsibility.readiness.ecosystem, VIOLET],
              ] as Array<[string, { score: number; total: number }, string]>).map(([label, domain, color]) => (
                // A domain with no findings classified to it was not measured:
                // it reads N/A, never the engine's weight-zero 100.
                <div key={label} className="rounded-md border border-white/8 bg-white/[0.02] p-3 text-center">
                  <div className="text-[9px] font-black uppercase tracking-wide text-white/40">{label}</div>
                  {domain.total > 0 ? (
                    <>
                      <div className="mt-1 text-xl font-semibold" style={{ color }}>{integerFmt(domain.score)}</div>
                      <div className="text-[9px] text-white/35">/100</div>
                    </>
                  ) : (
                    <>
                      <div className="mt-1 text-xl font-semibold text-white/45">N/A</div>
                      <div className="text-[9px] text-white/35">no findings in this domain</div>
                    </>
                  )}
                </div>
              ))}
            </div>
            <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
              {plan.sharedResponsibility.waves.map((wave) => {
                const tone = wave.domain === 'customer' ? CYAN : wave.domain === 'provider' ? BLUE : wave.domain === 'ecosystem' ? VIOLET : SLATEISH;
                const empty = wave.findingCount === 0;
                const statusColor = empty ? SLATEISH : wave.status === 'ready' ? EMERALD : wave.status === 'complete' ? GREEN : wave.status === 'blocked' ? RED : AMBER;
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
                    <span className="rounded px-1.5 py-0.5 text-[9px] font-black uppercase" style={{ color: statusColor, backgroundColor: `${statusColor}1a` }}>{empty ? 'No findings' : wave.status}</span>
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
            <SectionTitle
              suffix={
                <button
                  type="button"
                  onClick={() => setAssumptionsOpen(true)}
                  className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-cyan-300/90 transition-colors hover:bg-cyan-400/10 hover:text-cyan-200"
                >
                  <SlidersHorizontal className="h-3 w-3" /> Assumptions
                </button>
              }
            >
              Cost Forecasting
            </SectionTitle>
            <BarList rows={plan.costForecast.lines.map((l) => ({ label: l.category, value: l.costUsd }))} colorFor={() => EMERALD} max={Math.max(1, ...plan.costForecast.lines.map((l) => l.costUsd))} />

            {/* Categories with no supporting inventory are reported, never costed:
                a budget line for hardware the scan never found is a fabricated number. */}
            {plan.costForecast.excludedCategories?.length ? (
              <div className="mt-3 rounded-md border border-white/8 bg-white/[0.02] p-2.5">
                <div className="text-[9.5px] font-bold uppercase tracking-wider text-white/40">Not costed — no evidence</div>
                <ul className="mt-1.5 space-y-1">
                  {plan.costForecast.excludedCategories.map((entry) => (
                    <li key={entry.category} className="flex flex-wrap items-baseline gap-x-1.5 text-[10.5px] leading-snug">
                      <span className="font-semibold text-white/65">{entry.category}</span>
                      <span className="text-white/40">— {entry.reason}</span>
                      {entry.route ? (
                        <Link to={entry.route} className="text-cyan-300/80 underline decoration-cyan-400/30 underline-offset-2 hover:text-cyan-200">
                          connect
                        </Link>
                      ) : null}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}

            <div className="mt-3 grid grid-cols-2 gap-2">
              <div className="rounded-md border border-white/8 bg-black/20 p-3">
                <div className="text-lg font-semibold" style={{ color: EMERALD }}>{usd(plan.costForecast.totalUsd)}</div>
                <div className="text-[10px] uppercase tracking-wide text-white/45">Total Migration Cost</div>
                {plan.costForecast.totalHours ? (
                  <div className="mt-1 font-mono text-[9.5px] text-white/35">
                    {plan.costForecast.totalHours.toLocaleString()} hrs × {usd(plan.costForecast.blendedRateUsd ?? 0)}/hr
                  </div>
                ) : null}
              </div>
              <div className="rounded-md border border-white/8 bg-black/20 p-3">
                <div
                  className="text-lg font-semibold"
                  style={{ color: plan.costForecast.projectedRiskReductionValueUsd > 0 ? GREEN : 'rgba(255,255,255,0.45)' }}
                >
                  {plan.costForecast.projectedRiskReductionValueUsd > 0
                    ? usd(plan.costForecast.projectedRiskReductionValueUsd)
                    : 'Not modelled'}
                </div>
                <div className="text-[10px] uppercase tracking-wide text-white/45">Projected Risk-Reduction Value</div>
                {plan.costForecast.valueBasis ? (
                  <div className="mt-1 text-[9.5px] leading-snug text-white/35">{plan.costForecast.valueBasis}</div>
                ) : null}
              </div>
            </div>

            {/* Budget variance appears only when the tenant supplied a budget. */}
            {plan.costForecast.budget ? (
              <div
                className="mt-2 rounded-md border p-2.5 text-[10.5px]"
                style={{
                  borderColor: plan.costForecast.budget.status === 'over-budget' ? 'rgba(248,113,113,0.35)' : 'rgba(52,211,153,0.3)',
                  backgroundColor: plan.costForecast.budget.status === 'over-budget' ? 'rgba(248,113,113,0.07)' : 'rgba(52,211,153,0.06)',
                }}
              >
                <span className="font-bold" style={{ color: plan.costForecast.budget.status === 'over-budget' ? '#fca5a5' : GREEN }}>
                  {plan.costForecast.budget.status === 'over-budget' ? 'Over budget' : 'Within budget'}
                </span>
                <span className="text-white/55">
                  {' '}— estimate {usd(plan.costForecast.budget.estimateUsd)} vs approved {usd(plan.costForecast.budget.budgetUsd)} (
                  {plan.costForecast.budget.varianceUsd >= 0 ? '+' : ''}
                  {usd(plan.costForecast.budget.varianceUsd)}, {plan.costForecast.budget.variancePct}%)
                </span>
              </div>
            ) : null}

            {plan.costForecast.assumptions ? (
              <p className="mt-2 text-[9.5px] leading-relaxed text-white/35">{plan.costForecast.assumptions}</p>
            ) : null}
          </Panel>
        </section>

        <section>
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

        </div>}

        <dialog ref={dispatchDialog} className="mp-handoff-modal" aria-labelledby="mp-dispatch-heading" aria-describedby="mp-dispatch-description" onClose={() => { setDispatch(null); setHandoffIds([]); setRetryBatchId(null); setHandoffReview(EMPTY_REVIEW); setDispatchError(null); }} onCancel={(event) => { if (assetBusy) event.preventDefault(); }}>
          {dispatch && <form className="space-y-3" onSubmit={(event) => { event.preventDefault(); void executeHandoff(); }}>
            <h2 id="mp-dispatch-heading">Send to Live Migration Ops</h2>
            <p id="mp-dispatch-description">Approved proposal {dispatch.name}. The first selected asset is released first. Other selected assets wait for their wave.</p>
            <fieldset>
              <legend className="text-sm font-semibold">Assets to send ({selectedHandoffIds.length} selected)</legend>
              <div className="max-h-40 overflow-y-auto">
                {dispatchOptions.map((asset) => <label key={asset.id} className="flex min-h-11 items-center gap-2 text-sm">
                  <input type="checkbox" checked={handoffIds.includes(asset.id)} disabled={Boolean(assetBusy) || Boolean(retryBatchId)}
                    onChange={(event) => setHandoffIds((ids) => event.target.checked ? [...ids, asset.id] : ids.filter((id) => id !== asset.id))} />
                  <span className="break-words">{asset.name} · {asset.environment}</span>
                </label>)}
                {!dispatchOptions.length && <p className="mp-muted">There are no available assets in this selection. Review the current proposal.</p>}
              </div>
            </fieldset>
            {HANDOFF_REVIEW_FIELDS.map(({ key, label, hint, placeholder }) => <div key={key}>
              <label htmlFor={`mp-handoff-${key}`} className="block text-sm font-semibold">{label}</label>
              <span id={`mp-review-${key}`} className="mp-muted block text-xs">{hint}</span>
              <textarea id={`mp-handoff-${key}`} className="mp-field mt-1" rows={2} maxLength={500} required disabled={Boolean(assetBusy)} aria-describedby={`mp-review-${key}`} placeholder={placeholder}
                value={handoffReview[key]} onChange={(event) => setHandoffReview((current) => ({ ...current, [key]: event.target.value }))} />
            </div>)}
            {dispatchError && <p role="alert" className="text-[var(--mp-risk)]">{dispatchError}</p>}
            <div className="mp-actions">
              <button type="button" className="mp-button" onClick={() => dispatchDialog.current?.close()} disabled={Boolean(assetBusy)}>Cancel</button>
              <button type="submit" className="mp-button mp-button-primary" disabled={Boolean(assetBusy) || Boolean(approvalError) || !selectedHandoffIds.length || !parseHandoffReview(handoffReview)}>{assetBusy === 'dispatch' ? 'Sending…' : 'Send to Live Migration Ops'}</button>
            </div>
          </form>}
        </dialog>
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
