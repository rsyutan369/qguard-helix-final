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
import { useMigrationPlan, type MigrationStrategy } from '@/hooks/use-migration-plan';
import { DEFAULT_ASSET_FILTERS, useMigrationAssets, type AssetAlgorithm, type AssetDossier, type AssetSummaryRecord, type QueueEntry } from '@/hooks/use-migration-assets';
import { AssetMigrationGuide, MigrationMonitoring, MigrationOverview, SCANNER_PATH } from './_planner-guide';
import { labReadiness, type LabRun } from '@/lib/migration/sandbox-lab';
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
  labEvidence?: Array<{ id: string; asset_id: string; attached_at: string }>;
}

const PLAN_STATUS_TONES: Record<string, string> = {
  approved: EMERALD,
  pending_approval: AMBER,
  rejected: RED,
};

function ApprovalWorkflowPanel({ onDecision, queue, revision, onReviewExecution, busy: assetBusy }: {
  onDecision: () => void;
  queue: QueueEntry[];
  revision: string | null;
  onReviewExecution: (proposal: ApprovalPlan) => void;
  busy: string | null;
}) {
  const { session, user } = useAuth();
  const token = session?.access_token;
  const [plans, setPlans] = useState<ApprovalPlan[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [rejectingId, setRejectingId] = useState<string | null>(null);
  const [reason, setReason] = useState('');
  const [name, setName] = useState('');
  const [targets, setTargets] = useState<Record<string, string>>({});
  const [loadError, setLoadError] = useState<string | null>(null);
  const loadedRequest = useRef(0);

  const loadPlans = useCallback(async () => {
    if (!token) return;
    const revision = ++loadedRequest.current;
    try {
      const response = await fetch('/api/v1/migration-planner/plans', { headers: { Authorization: `Bearer ${token}` } });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      if (revision !== loadedRequest.current) return;
      setPlans(payload.data || []);
      setLoadError(null);
    } catch (err) {
      if (revision === loadedRequest.current) setLoadError(err instanceof Error ? err.message : 'Could not load approval records.');
    }
  }, [token]);

  useEffect(() => {
    void loadPlans();
  }, [loadPlans, revision]);

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
      <p className="mb-3 text-sm text-[var(--mp-muted)]">Save the current queue as a proposal with its asset order and evidence-based replacement candidates. Review it with the asset owner and test compatibility before approving execution.</p>
      {loadError && <p role="alert" className="mb-3 text-sm text-[var(--mp-risk)]">{loadError}</p>}
      {message && <p role="status" className="mb-3 text-sm">{message}</p>}
      <form className="mb-4 space-y-3" onSubmit={(event) => {
        event.preventDefault();
        if (busy || !queue.length || queue.length > 50) return;
        const selected = Object.fromEntries(queue.map((entry) => [entry.assetId, entry.targets?.includes(targets[entry.assetId]) ? targets[entry.assetId] : '']));
        void post('/plans', { name, targets: selected, assetIds: queue.map((entry) => entry.assetId) }, 'Proposal saved and submitted for approval.');
      }}>
        <label className="block text-xs">Plan name <input className="mp-field mt-1" value={name} onChange={(event) => setName(event.target.value)} maxLength={160} placeholder="PQC migration plan (optional)" /></label>
        {queue.some((entry) => entry.targets?.length) && <details className="mp-disclosure">
          <summary>Choose preferred planning targets</summary>
          <p className="mp-muted mt-2">These candidates describe the proposed change. Confirm what the agent or connector can apply before execution.</p>
          <div className="mt-2 grid gap-2 sm:grid-cols-2">
            {queue.filter((entry) => entry.targets?.length).map((entry) => <label key={entry.assetId} className="block min-w-0 break-words text-xs">
              {entry.name}
              <select className="mp-field mt-1" value={targets[entry.assetId] || ''} onChange={(event) => setTargets((current) => ({ ...current, [entry.assetId]: event.target.value }))}>
                <option value="">Leave for compatibility review</option>
                {entry.targets.map((target) => <option key={target} value={target}>{target}</option>)}
              </select>
            </label>)}
          </div>
        </details>}
        <button className="mp-button mp-button-primary" type="submit" disabled={busy || !user || !queue.length || queue.length > 50}>
          <ScrollText size={16} aria-hidden="true" /> {busy ? 'Working…' : 'Submit queue for approval'}
        </button>
        {queue.length > 50 && <p className="w-full text-xs text-[var(--mp-risk)]">Review a batch of up to 50 assets.</p>}
      </form>
      {plans.length ? (
        <div className="space-y-2">
          {plans.map((plan) => {
            const tone = PLAN_STATUS_TONES[plan.status.toLowerCase()] || SLATEISH;
            const canDispatch = plan.status === 'approved' && plan.scope.length > 0;
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
                      <button className="mp-button" disabled={busy} onClick={() => void post(`/plans/${encodeURIComponent(plan.id)}/approval`, { decision: 'approve' }, 'Approval recorded.')}>Approve</button>
                      <button className="mp-button" disabled={busy} onClick={() => setRejectingId(rejectingId === plan.id ? null : plan.id)}>Reject</button>
                    </div>
                  ) : null}
                  {canDispatch && <button className="mp-button" disabled={Boolean(assetBusy)} onClick={() => onReviewExecution(plan)}>Review approved execution</button>}
                </div>
                {plan.scope.length > 0 && (
                  <details className="mp-disclosure mt-2">
                    <summary>{plan.scope.length} assets in approved or proposed scope</summary>
                    <ul className="space-y-2 px-2 py-2 text-xs">
                      {plan.scope.map((asset) => <li key={asset.id} className="break-words"><strong>{asset.name}</strong> · {asset.priority} · {asset.owner}
                        {asset.preferredTarget && <p>Preferred target · {asset.preferredTarget}</p>}
                        {asset.algorithms.filter((algorithm) => algorithm.classification === 'vulnerable').map((algorithm) => <p key={`${algorithm.algorithm}:${algorithm.category}`} className="mp-muted">{algorithm.algorithm} → {algorithm.target}</p>)}
                      </li>)}
                    </ul>
                  </details>
                )}
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
  const view = VIEWS.find((item) => item.id === params.get('view'))?.id ?? 'findings';
  const requestedAsset = params.get('asset');
  const labRun = params.get('labRun');
  const [refreshing, setRefreshing] = useState(false);
  const [evidenceExporting, setEvidenceExporting] = useState(false);
  const [dispatch, setDispatch] = useState<{ assets: HandoffAsset[]; proposal?: ApprovalPlan } | null>(null);
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
      next.set('view', 'findings');
      return next;
    });
  };

  const refreshPlanner = useCallback(async () => {
    setRefreshing(true);
    try { await Promise.all([refresh(), refreshAssets()]); }
    finally { setRefreshing(false); }
  }, [refresh, refreshAssets]);

  const reviewQueue = (entries: QueueEntry[]) => {
    if (entries.length > 50) {
      setNotice('Choose a batch of up to 50 assets for execution.');
      return;
    }
    setDispatch({ assets: entries.map((asset) => ({ ...asset, id: asset.assetId })) });
  };

  const executeHandoff = async () => {
    if (!dispatch || assetBusy) return;
    setNotice(null);
    try {
      const result = await sendToLiveMigration(dispatch.assets, {}, 'start', dispatch.proposal?.id);
      dispatchDialog.current?.close();
      navigate(result.liveMigrationUrl);
    } catch (err) {
      dispatchDialog.current?.close();
      setNotice(err instanceof Error ? err.message : 'Could not queue the migration.');
    }
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
        <nav className="mp-nav" aria-label="Migration Planner sections">
          {VIEWS.map(({ id, label, icon: Icon }) => (
            <button key={id} type="button" aria-current={view === id ? 'page' : undefined} onClick={() => goTo(id)}><Icon size={17} aria-hidden="true" /> {label}</button>
          ))}
        </nav>

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
              onQueue={(id) => void enqueue([id])}
              loading={portfolioLoading}
              queue={queue.entries}
              onDequeue={(id) => void dequeue(id)}
              onReorder={(ids) => void reorderQueue(ids)}
              onApplyRecommended={() => void applyRecommendedOrder()}
              onDispatchQueue={() => reviewQueue(queue.entries)}
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
                    <p>Review the queue in priority order. Confirm targets with asset owners, test providers and dependencies in a representative environment, then submit the scope for change approval.</p>
                    <div className="mp-actions">
                      <button className="mp-button" onClick={() => goTo('findings')}>Review findings <ArrowRight size={16} aria-hidden="true" /></button>
                      <Link className="mp-button" to="/dashboard/migration-sandbox">Open Migration Sandbox</Link>
                    </div>
                    {queueError && <p role="alert">{queueError}</p>}
                  </section>
                  <ApprovalWorkflowPanel queue={queue.entries} revision={lastVerifiedAt} onDecision={() => void refresh()} onReviewExecution={(proposal) => setDispatch({ assets: proposal.scope, proposal })} busy={assetBusy} />
                </>
              ) : requestedAsset ? (
                <div ref={dossierTarget} tabIndex={-1} className="min-w-0">
                  {dossierError && <div role="alert" className="mp-card mp-intro mb-3">
                    <h2>Could not load this asset</h2><p>{dossierError}</p>
                    <div className="mp-actions"><button className="mp-button" onClick={() => loadAsset(requestedAsset)}>Retry</button><button className="mp-button" onClick={() => selectAsset(null)}>Back to findings</button></div>
                  </div>}
                  {dossier?.id === requestedAsset ? (
                    <AssetDossierView asset={dossier} position={position} loading={dossierLoading} changedFields={changedFields}
                      onQueue={() => dossier.queued ? goTo('planning') : void enqueue([dossier.id])}
                      onDispatch={() => setDispatch({ assets: [dossier] })} onClear={() => selectAsset(null)} busy={assetBusy}>
                      <AssetMigrationGuide key={dossier.id} asset={dossier} busy={Boolean(assetBusy) || evidenceExporting}
                        onPlan={() => dossier.queued ? goTo('planning') : void enqueue([dossier.id])}
                        onSandbox={() => void openSandbox(dossier)} onDispatch={() => setDispatch({ assets: [dossier] })}
                        onReport={() => void exportAssetEvidence(dossier)} />
                    </AssetDossierView>
                  ) : !dossierError ? <AssetDossierSkeleton /> : null}
                </div>
              ) : (
                <>
                  <section className="mp-card mp-intro">
                    <h2>{portfolio.generatedAt && !portfolio.totalUnfiltered ? 'Discover your first assets' : 'Start with your highest-priority finding'}</h2>
                    <p>{portfolio.generatedAt && !portfolio.totalUnfiltered ? 'Run a PQC discovery scan or connect an asset source. Detected algorithms and findings appear here when evidence is available.' : 'Select an asset to see the detected configuration, what it exposes, and what to do next.'}</p>
                    <div className="mp-actions">
                      {portfolio.recommendedOrder[0] && <button type="button" className="mp-button mp-button-primary" onClick={() => selectAsset(portfolio.recommendedOrder[0].assetId)}>Review {portfolio.recommendedOrder[0].name} <ArrowRight size={16} aria-hidden="true" /></button>}
                      <Link className="mp-button" to={SCANNER_PATH}>Open PQC Scanner</Link>
                      {portfolio.summary.vulnerableAssets > 0 && <button className="mp-button" onClick={() => setFilters({ ...DEFAULT_ASSET_FILTERS, posture: 'needs-migration' })}>Filter to vulnerable assets</button>}
                    </div>
                  </section>
                  {portfolio.generatedAt && portfolio.totalUnfiltered > 0 && <details className="mp-disclosure">
                    <summary>Recommended order and portfolio evidence</summary>
                    <div className="mt-2"><AssetPortfolioOverview summary={portfolio.summary} recommendedOrder={portfolio.recommendedOrder} reconciliation={portfolio.reconciliation} onSelect={selectAsset} onQueue={(id) => void enqueue([id])} /></div>
                  </details>}
                </>
              )}
            </div>
          </section>
        )}

        {view === 'execution' && <MigrationMonitoring />}

        {view === 'analytics' && <div className="grid min-w-0 gap-4">
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

        <dialog ref={dispatchDialog} className="mp-dialog" aria-labelledby="mp-dispatch-heading" onClose={() => setDispatch(null)} onCancel={(event) => { if (assetBusy) event.preventDefault(); }}>
          {dispatch && <>
            <h2 id="mp-dispatch-heading">Confirm migration handoff</h2>
            <p>{dispatch.proposal ? `Approved proposal ${dispatch.proposal.name}.` : 'Starting here records your approval for this execution.'} Confirm the compatibility check, change window, and rollback plan before queueing agent work.</p>
            <ul className="max-h-48 space-y-1 overflow-y-auto text-sm">
              {dispatch.assets.map((asset) => <li key={asset.id} className="break-words">{asset.name} · {asset.environment}</li>)}
            </ul>
            <p>Live Migration Ops shows agent and connector requirements, validation results, and execution controls.</p>
            <div className="mp-actions">
              <button type="button" className="mp-button" autoFocus onClick={() => dispatchDialog.current?.close()} disabled={Boolean(assetBusy)}>Cancel</button>
              <button type="button" className="mp-button mp-button-primary" onClick={() => void executeHandoff()} disabled={Boolean(assetBusy)}>{assetBusy === 'dispatch' ? 'Queueing…' : 'Queue migration'}</button>
            </div>
          </>}
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
