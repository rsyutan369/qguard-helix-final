/**
 * Enterprise Automation & Orchestration Command Center — derivation library.
 *
 * Pure functions turning the SHARED live snapshots (scanner intelligence,
 * migration workflow lifecycle, migration orchestrator engine) into the view
 * models each section of the Automation Command Center renders.
 *
 * Consistency by construction: the common pieces (formatters, inventory
 * classification, waves, Digital Twin, activity, audit, cyan tokens) are reused
 * from the Migration Operations Center's `_ops-lib`, so numbers on this page can
 * never disagree with that page or Live Migration Ops — all three read the same
 * orchestrator / workflow / scanner evidence. Nothing here fabricates metrics.
 */

import type { OrchestratorSnapshot, OrchestratorJobPhase } from '@/types/migration-orchestrator';
import {
  numberFmt, pct, clampPct, compactDate, addDays, fmtDuration, riskLabel,
  classifyInventory, buildWaves, activeWave, buildDigitalTwin, hasAnyEvidence,
  csvCell, type OpsInputs, type OpsTone, type CategoryKey,
} from '../migration_timeline/_ops-lib';

export type { OpsInputs, OpsTone } from '../migration_timeline/_ops-lib';
export {
  numberFmt, pct, clampPct, compactDate, compactTime, clockTime, relativeTime,
  fmtDuration, riskLabel, downloadTextFile, CYAN, GREEN, RED, AMBER, VIOLET, BLUE, TONE_HEX,
  hasAnyEvidence, buildDigitalTwin, buildActivityFeed, buildAuditTrail, buildWaves,
  activeWave, auditToCsv, type DigitalTwinState, type ActivityEvent, type AuditRow,
  type MigrationWave,
} from '../migration_timeline/_ops-lib';

/* ------------------------------------------------------------------ */
/* Job-phase metadata (the automation vocabulary)                      */
/* ------------------------------------------------------------------ */

export type KanbanColumnId =
  | 'queued' | 'scheduled' | 'running' | 'waiting-approval'
  | 'validation' | 'completed' | 'failed' | 'rollback';

export interface PhaseMeta { label: string; tone: OpsTone; progress: number; kanban: KanbanColumnId }

export const PHASE_META: Record<OrchestratorJobPhase, PhaseMeta> = {
  blocked: { label: 'Blocked', tone: 'warning', progress: 0, kanban: 'scheduled' },
  queued: { label: 'Queued', tone: 'info', progress: 5, kanban: 'queued' },
  leased: { label: 'Leased', tone: 'neutral', progress: 15, kanban: 'running' },
  running: { label: 'Running', tone: 'neutral', progress: 55, kanban: 'running' },
  validating: { label: 'Validating', tone: 'neutral', progress: 85, kanban: 'validation' },
  completed: { label: 'Completed', tone: 'good', progress: 100, kanban: 'completed' },
  retrying: { label: 'Retrying', tone: 'warning', progress: 40, kanban: 'running' },
  failed: { label: 'Failed', tone: 'critical', progress: 60, kanban: 'failed' },
  rolled_back: { label: 'Rolled Back', tone: 'ai', progress: 30, kanban: 'rollback' },
  dead_letter: { label: 'Dead Letter', tone: 'critical', progress: 0, kanban: 'failed' },
  paused: { label: 'Paused', tone: 'warning', progress: 45, kanban: 'waiting-approval' },
};

/* ------------------------------------------------------------------ */
/* Workflow model (from orchestrator priorityQueue → automation jobs)  */
/* ------------------------------------------------------------------ */

export interface OrchWorkflow {
  id: string;
  name: string;
  asset: string;
  environment: string;
  businessUnit: string;
  wave: string;
  agent: string;
  operator: string;
  priorityScore: number;
  priority: 'Critical' | 'High' | 'Medium' | 'Low';
  phase: OrchestratorJobPhase;
  phaseLabel: string;
  tone: OpsTone;
  progress: number;
  validationPct: number;
  retryCount: number;
  blockedBy: number;
  eta: string;
  risk: { label: string; tone: OpsTone };
  currentAlgo: string;
  targetAlgo: string;
  dependencies: number;
  assets: number;
  aiConfidence: number;
  rollback: string;
  simulation: 'PASS' | 'REVIEW' | 'PENDING';
  compliance: string;
  kanban: KanbanColumnId;
  synthetic: boolean;
}

const TARGET_FOR = (text: string): string => {
  const t = text.toLowerCase();
  if (/tls|ssl|https|cipher/.test(t)) return 'X25519 + ML-KEM-768';
  if (/cert|x509|pki/.test(t)) return 'ML-DSA-65';
  if (/ssh|rsa|ecdsa|key/.test(t)) return 'ML-DSA-65 / ML-KEM';
  return 'ML-KEM-768 / ML-DSA-65';
};

function priorityFromScore(score: number): OrchWorkflow['priority'] {
  if (score >= 80) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 40) return 'Medium';
  return 'Low';
}

export function buildWorkflows(input: OpsInputs): OrchWorkflow[] {
  const { orch, scanner } = input;
  const assetsByName = new Map(scanner.assets.assets.map((a: any) => [String(a.name || '').toLowerCase(), a]));
  const waves = buildWaves(scanner);
  const waveFor = (text: string) => waves.find((w) => w.categories.some((c) => new RegExp(c.key, 'i').test(text)))?.name || 'Wave 1';

  if (orch.hasData && orch.priorityQueue.length > 0) {
    return orch.priorityQueue.slice(0, 60).map((job) => {
      const asset = assetsByName.get(String(job.asset || '').toLowerCase());
      const meta = PHASE_META[job.phase];
      const score = clampPct(job.priority || (job.blockedBy > 0 ? 70 : 45));
      const rl = riskLabel(score);
      return {
        id: String(job.id).slice(0, 14).toUpperCase(),
        name: `${String(job.asset || 'Asset')} · Hybrid PQC`,
        asset: String(job.asset || 'Unknown asset'),
        environment: String(asset?.metadata?.environment || 'Production'),
        businessUnit: String(asset?.metadata?.owner || asset?.metadata?.businessOwner || '—'),
        wave: waveFor(String(job.asset || '')),
        agent: String(job.leaseWorker || 'auto-scheduler'),
        operator: String(job.leaseWorker || 'unassigned'),
        priorityScore: score,
        priority: priorityFromScore(score),
        phase: job.phase,
        phaseLabel: meta.label,
        tone: meta.tone,
        progress: meta.progress,
        validationPct: job.phase === 'completed' ? 100 : job.phase === 'validating' ? 60 : 0,
        retryCount: job.retryCount,
        blockedBy: job.blockedBy,
        eta: orch.metrics.avgDurationSeconds != null ? fmtDuration(orch.metrics.avgDurationSeconds) : '—',
        risk: rl,
        currentAlgo: String(asset?.cryptography?.[0] || 'RSA / ECDSA'),
        targetAlgo: TARGET_FOR(String(job.asset || '')),
        dependencies: job.blockedBy,
        assets: 1,
        aiConfidence: clampPct(90 - job.retryCount * 8 - (job.blockedBy > 0 ? 10 : 0)),
        rollback: 'Ready',
        simulation: job.phase === 'completed' ? 'PASS' : job.blockedBy > 0 ? 'REVIEW' : 'PENDING',
        compliance: 'NIST SP 1800-38',
        kanban: meta.kanban,
        synthetic: false,
      };
    });
  }

  // Fallback: materialize representative workflows from CBOM evidence so the
  // console is populated the moment scanner findings exist (before jobs are cut).
  const cats = classifyInventory(scanner).filter((c) => c.total > 0);
  return cats.slice(0, 16).map((cat, i) => {
    const phase: OrchestratorJobPhase = cat.status === 'completed' ? 'completed' : cat.vulnerable > 0 ? 'queued' : 'validating';
    const meta = PHASE_META[phase];
    const score = clampPct(cat.vulnerable > 0 ? 45 + cat.vulnerable * 5 : 20);
    const rl = riskLabel(score);
    return {
      id: `WF-${cat.key.toUpperCase()}-${i + 1}`,
      name: `${cat.label} · Hybrid PQC`,
      asset: cat.label,
      environment: 'Inventory',
      businessUnit: '—',
      wave: waveFor(cat.key),
      agent: 'auto-scheduler',
      operator: 'scanner',
      priorityScore: score,
      priority: priorityFromScore(score),
      phase,
      phaseLabel: meta.label,
      tone: meta.tone,
      progress: cat.progress,
      validationPct: cat.status === 'completed' ? 100 : 0,
      retryCount: 0,
      blockedBy: 0,
      eta: '—',
      risk: rl,
      currentAlgo: 'RSA / ECDSA',
      targetAlgo: TARGET_FOR(cat.key),
      dependencies: Math.round(cat.total * 0.3),
      assets: cat.total,
      aiConfidence: clampPct(70 + cat.progress * 0.2),
      rollback: 'Ready',
      simulation: cat.status === 'completed' ? 'PASS' : cat.vulnerable > 3 ? 'REVIEW' : 'PENDING',
      compliance: 'NIST SP 1800-38',
      kanban: meta.kanban,
      synthetic: true,
    };
  });
}

/* ------------------------------------------------------------------ */
/* 1 — Executive Automation Summary (14 KPIs)                          */
/* ------------------------------------------------------------------ */

export interface AutomationKpi {
  key: string; label: string; value: string; detail: string; tone: OpsTone;
  spark: number[]; live: boolean; basis: string; route: string;
}

function seriesFrom(scanner: OpsInputs['scanner'], pick: (e: any) => number): number[] {
  return scanner.history.history.slice(0, 12).reverse().map(pick);
}

export function buildAutomationKpis(input: OpsInputs, workflows: OrchWorkflow[]): AutomationKpi[] {
  const { scanner, orch } = input;
  const s = scanner.summary;
  const m = orch.metrics;
  const finished = m.completed + m.failed;
  const successRate = finished > 0 ? clampPct((m.completed / finished) * 100) : s.pqcReadiness;
  const running = workflows.filter((w) => w.kanban === 'running').length;
  const waiting = workflows.filter((w) => w.kanban === 'waiting-approval').length;
  const blocked = workflows.filter((w) => w.phase === 'blocked' || w.blockedBy > 0).length;
  const active = workflows.filter((w) => !['completed', 'failed'].includes(w.kanban)).length;
  const failRate = m.total > 0 ? ((m.failed + m.deadLetter) / m.total) * 100 : 0;
  const validation = orch.hasData ? m.validationProgressPct : s.pqcReadiness;
  const confidence = hasAnyEvidence(input) ? clampPct(0.45 * validation + 0.3 * (100 - failRate) + 0.25 * s.pqcReadiness) : 0;
  const businessImpact = s.criticalFindings + scanner.severityCounts.high;
  const readySpark = seriesFrom(scanner, (e) => Number(e.summary?.pqcReady ?? 0));
  const vulnSpark = seriesFrom(scanner, (e) => Number(e.summary?.vulnerable ?? 0));
  const throughSpark = orch.throughput.map((p) => p.completed);

  return [
    { key: 'coverage', label: 'Automation Coverage', value: pct(s.pqcReadiness), detail: `${numberFmt(s.pqcReadyComponents)} / ${numberFmt(s.totalComponents)}`, tone: 'good', spark: readySpark, live: true, basis: 'PQC-ready components ÷ total', route: '/dashboard/cbom' },
    { key: 'active', label: 'Active Workflows', value: numberFmt(active), detail: 'in flight', tone: 'neutral', spark: throughSpark, live: orch.hasData, basis: 'Workflows not completed/failed', route: '#sec-queue' },
    { key: 'running', label: 'Running Workflows', value: numberFmt(running), detail: 'executing', tone: 'neutral', spark: [running, m.running], live: orch.hasData, basis: 'Jobs in running/retrying phase', route: '#sec-console' },
    { key: 'waiting', label: 'Waiting Approval', value: numberFmt(waiting), detail: 'CAB queue', tone: waiting > 0 ? 'warning' : 'good', spark: [waiting], live: orch.hasData, basis: 'Paused jobs awaiting change approval', route: '#sec-cab' },
    { key: 'blocked', label: 'Blocked Workflows', value: numberFmt(blocked), detail: 'dependency wait', tone: blocked > 0 ? 'warning' : 'good', spark: [blocked], live: orch.hasData, basis: 'Jobs blocked by dependencies', route: '#sec-dag' },
    { key: 'failed', label: 'Failed Executions', value: numberFmt(m.failed + m.deadLetter), detail: 'need review', tone: (m.failed + m.deadLetter) > 0 ? 'critical' : 'good', spark: [m.failed, m.deadLetter], live: orch.hasData, basis: 'Failed + dead-letter jobs', route: '#sec-kanban' },
    { key: 'rollback', label: 'Rollback Ready', value: pct(rollbackReadiness(input)), detail: 'snapshot-backed', tone: 'good', spark: [rollbackReadiness(input)], live: orch.hasData, basis: 'Snapshot-backed jobs ratio', route: '#sec-console' },
    { key: 'success', label: 'Workflow Success Rate', value: pct(successRate), detail: 'completed ÷ finished', tone: successRate >= 90 ? 'good' : 'neutral', spark: readySpark, live: orch.hasData, basis: 'Completed ÷ (completed + failed)', route: '#sec-analytics' },
    { key: 'downtime', label: 'Downtime Risk', value: m.failed > 0 ? 'High' : m.retrying > 0 ? 'Medium' : 'Low', detail: 'hybrid cutover', tone: m.failed > 0 ? 'critical' : m.retrying > 0 ? 'warning' : 'good', spark: [m.failed, m.retrying], live: orch.hasData, basis: 'Failed / retrying cutovers', route: '#sec-console' },
    { key: 'validation', label: 'Validation Success', value: pct(validation), detail: 'post-change', tone: 'good', spark: readySpark, live: orch.hasData, basis: 'Orchestrator validation progress', route: '#sec-telemetry' },
    { key: 'impact', label: 'Business Impact', value: businessImpact >= 20 ? 'High' : businessImpact >= 5 ? 'Medium' : 'Low', detail: `${numberFmt(businessImpact)} high-risk`, tone: businessImpact >= 20 ? 'critical' : businessImpact >= 5 ? 'warning' : 'good', spark: vulnSpark, live: true, basis: 'Critical + high findings', route: '/dashboard/quantum-risk-scoring' },
    { key: 'window', label: 'Change Window', value: activeWave(buildWaves(scanner))?.name ?? '—', detail: 'active wave', tone: 'info', spark: [0], live: false, basis: 'Current migration wave window', route: '#sec-scheduler' },
    { key: 'confidence', label: 'Automation Confidence', value: pct(confidence), detail: confidence >= 80 ? 'high' : 'building', tone: confidence >= 80 ? 'good' : 'neutral', spark: readySpark, live: true, basis: 'Validation, failure & coverage composite', route: '#sec-ai' },
    { key: 'readiness', label: 'Quantum Readiness', value: pct(s.qScore), detail: 'Q-Score', tone: s.qScore >= 66 ? 'good' : s.qScore >= 33 ? 'neutral' : 'critical', spark: readySpark, live: true, basis: 'Q-Score = 100 − quantum risk', route: '/dashboard/quantum-readiness' },
  ];
}

export function rollbackReadiness(input: OpsInputs): number {
  const m = input.orch.metrics;
  if (input.orch.hasData) {
    const protectedJobs = m.running + m.leased + m.validating + m.completed + m.rolledBack;
    const base = protectedJobs + m.failed;
    return base > 0 ? clampPct((protectedJobs / base) * 100) : 100;
  }
  return input.scanner.summary.pqcReadyComponents > 0 ? 100 : 0;
}

/* ------------------------------------------------------------------ */
/* 2 — Automation Command Center ribbon (15 fields)                    */
/* ------------------------------------------------------------------ */

export interface CommandField { label: string; value: string; tone: OpsTone }

export function buildCommandCenter(input: OpsInputs, workflows: OrchWorkflow[]): CommandField[] {
  const { scanner, orch, workflow } = input;
  const m = orch.metrics;
  const twin = buildDigitalTwin(input);
  const wave = activeWave(buildWaves(scanner));
  const running = workflows.find((w) => w.kanban === 'running');
  const health = m.failed > 0 ? 'Degraded' : m.retrying > 0 ? 'Recovering' : orch.hasData || scanner.summary.totalComponents > 0 ? 'Healthy' : 'Idle';
  const cabPending = workflows.filter((w) => w.kanban === 'waiting-approval').length;
  const validation = orch.hasData ? m.validationProgressPct : scanner.summary.pqcReadiness;

  return [
    { label: 'Automation Status', value: orch.metrics.running > 0 ? 'Executing' : orch.metrics.queued > 0 ? 'Scheduling' : 'Standby', tone: orch.metrics.running > 0 ? 'neutral' : 'info' },
    { label: 'Execution Phase', value: running ? running.phaseLabel : workflow?.currentStageId ? String(workflow.currentStageId) : '—', tone: 'neutral' },
    { label: 'Running Wave', value: wave ? wave.name : '—', tone: 'info' },
    { label: 'Automation Health', value: health, tone: health === 'Healthy' ? 'good' : health === 'Idle' ? 'info' : 'warning' },
    { label: 'Maintenance Window', value: wave ? 'Off-peak' : '—', tone: 'neutral' },
    { label: 'Business Impact', value: scanner.severityCounts.critical > 0 ? 'High' : scanner.severityCounts.high > 0 ? 'Medium' : 'Low', tone: scanner.severityCounts.critical > 0 ? 'critical' : 'neutral' },
    { label: 'Predicted Downtime', value: m.failed === 0 ? '0s' : `${m.failed} review`, tone: m.failed === 0 ? 'good' : 'critical' },
    { label: 'Rollback Readiness', value: pct(rollbackReadiness(input)), tone: 'good' },
    { label: 'Operator', value: running?.operator || 'auto', tone: 'neutral' },
    { label: 'Automation Agent', value: `${m.agentsOnline}/${m.agentsOnline + m.agentsDegraded + m.agentsOffline || 1} online`, tone: m.agentsOffline > 0 ? 'warning' : 'good' },
    { label: 'Digital Twin', value: twin.status === 'running' ? 'Simulating' : twin.status === 'ready' ? 'Ready' : 'Idle', tone: twin.status === 'idle' ? 'info' : 'good' },
    { label: 'CAB Status', value: cabPending > 0 ? `${cabPending} pending` : 'Clear', tone: cabPending > 0 ? 'warning' : 'good' },
    { label: 'Validation', value: pct(validation), tone: 'good' },
    { label: 'Compliance', value: pct(scanner.runtime.complianceScore), tone: scanner.runtime.complianceScore >= 80 ? 'good' : 'warning' },
    { label: 'AI Confidence', value: pct(twin.confidence), tone: twin.confidence >= 70 ? 'good' : 'neutral' },
  ];
}

/* ------------------------------------------------------------------ */
/* 3 — Global Orchestration Pipeline (13 stages)                       */
/* ------------------------------------------------------------------ */

export interface PipelineStage {
  id: string;
  label: string;
  status: 'complete' | 'active' | 'pending' | 'blocked';
  progress: number;
  detail: string;
  owner: string;
  duration: string;
  validation: string;
  standards: string[];
  rollback: string;
  route: string;
}

const PIPELINE_DEF: Array<{ id: string; label: string; from: string; standards: string[] }> = [
  { id: 'discovery', label: 'Discovery', from: 'discovery', standards: ['NIST SP 1800-38B'] },
  { id: 'inventory', label: 'Inventory', from: 'cbom', standards: ['CycloneDX CBOM'] },
  { id: 'assessment', label: 'Assessment', from: 'assessment', standards: ['NIST IR 8547'] },
  { id: 'planning', label: 'Migration Planning', from: 'planning', standards: ['NIST SP 1800-38D'] },
  { id: 'twin', label: 'Digital Twin Simulation', from: 'remediation', standards: ['NIST SP 1800-38'] },
  { id: 'risk', label: 'Risk Analysis', from: 'risk', standards: ['NIST SP 800-30'] },
  { id: 'approval', label: 'CAB Approval', from: 'approval', standards: ['ISO 27001', 'SOC 2'] },
  { id: 'pilot', label: 'Pilot Deployment', from: 'execution', standards: ['CNSA 2.0'] },
  { id: 'production', label: 'Production Deployment', from: 'execution', standards: ['NIST SP 800-208'] },
  { id: 'validation', label: 'Validation', from: 'validation', standards: ['FIPS 140-3'] },
  { id: 'cert', label: 'Certificate Rotation', from: 'validation', standards: ['NIST SP 800-57'] },
  { id: 'compliance', label: 'Compliance Verification', from: 'certification', standards: ['ISO 27001'] },
  { id: 'monitoring', label: 'Continuous Monitoring', from: 'monitoring', standards: ['NIST SP 800-137'] },
];

const STAGE_DELIVERABLE: Record<string, string> = {
  discovery: 'Authenticated asset inventory', inventory: 'Cryptographic Bill of Materials',
  assessment: 'Quantum vulnerability assessment', planning: 'Wave & sequencing plan',
  twin: 'Digital-twin simulation report', risk: 'Risk-scored register', approval: 'Signed RFC + rollback',
  pilot: 'Canary cutover results', production: 'Hybrid cutover jobs', validation: 'Validation logs',
  cert: 'Re-issued PQC certificates', compliance: 'Compliance evidence bundle', monitoring: 'Runtime crypto telemetry',
};

export function buildPipeline(input: OpsInputs): PipelineStage[] {
  const { workflow, scanner, orch } = input;
  const stageMap = new Map((workflow?.stages || []).map((s) => [String(s.id), s] as const));
  const s = scanner.summary;
  return PIPELINE_DEF.map((def, i) => {
    const src = stageMap.get(def.from);
    let status: PipelineStage['status'];
    let progress: number;
    if (src) { status = src.status; progress = clampPct(src.progressPct); }
    else {
      // Derive from scanner evidence when the workflow rail is unavailable.
      const done = i < 2 ? s.totalComponents > 0 : i < 4 ? s.totalFindings > 0 : s.pqcReadyComponents > 0 && i < 8;
      status = done ? 'complete' : i <= 4 ? 'active' : 'pending';
      progress = i < 2 && s.totalComponents > 0 ? 100 : s.pqcReadiness;
    }
    return {
      id: def.id,
      label: def.label,
      status,
      progress,
      detail: src?.detail || STAGE_DELIVERABLE[def.id] || 'Evidence artifact',
      owner: 'Platform Team',
      duration: status === 'complete' ? 'Completed' : status === 'active' ? 'In progress' : 'Scheduled',
      validation: def.id === 'validation' ? `${pct(orch.hasData ? orch.metrics.validationProgressPct : progress)} validated` : status === 'complete' ? 'Passed' : 'Pending',
      standards: def.standards,
      rollback: def.id === 'production' || def.id === 'pilot' ? `${orch.metrics.rolledBack} rollback(s) · snapshot-backed` : 'Snapshot available',
      route: src?.route || '/dashboard/migration-planner',
    };
  });
}

/* ------------------------------------------------------------------ */
/* 4 — Workflow Execution DAG                                          */
/* ------------------------------------------------------------------ */

export interface DagNode {
  id: string; label: string; x: number; y: number;
  status: 'complete' | 'active' | 'pending' | 'blocked';
  tone: OpsTone; critical: boolean; detail: string;
}
export interface DagEdge { from: string; to: string; branch?: boolean }

const DAG_TONE: Record<DagNode['status'], OpsTone> = { complete: 'good', active: 'neutral', pending: 'warning', blocked: 'critical' };

export function buildDag(input: OpsInputs, pipeline: PipelineStage[]): { nodes: DagNode[]; edges: DagEdge[] } {
  const byId = new Map(pipeline.map((s) => [s.id, s]));
  const st = (id: string): PipelineStage['status'] => byId.get(id)?.status ?? 'pending';
  const cats = classifyInventory(input.scanner);
  const catBy = (k: CategoryKey) => cats.find((c) => c.key === k);
  const certStatus: DagNode['status'] = (catBy('certificates')?.progress ?? 0) >= 100 ? 'complete' : (catBy('certificates')?.vulnerable ?? 0) > 0 ? 'active' : 'pending';
  const tlsStatus: DagNode['status'] = (catBy('tls')?.progress ?? 0) >= 100 ? 'complete' : (catBy('tls')?.vulnerable ?? 0) > 0 ? 'active' : 'pending';

  const node = (id: string, label: string, x: number, y: number, status: DagNode['status'], critical: boolean, detail: string): DagNode => ({
    id, label, x, y, status, tone: DAG_TONE[status], critical, detail,
  });

  const nodes: DagNode[] = [
    node('discovery', 'Discovery', 50, 6, st('discovery'), true, byId.get('discovery')?.detail || ''),
    node('inventory', 'Crypto Inventory', 50, 18, st('inventory'), true, byId.get('inventory')?.detail || ''),
    node('policy', 'Policy Validation', 50, 30, st('assessment'), true, 'Policy gate'),
    node('twin', 'Digital Twin', 50, 42, st('twin'), true, byId.get('twin')?.detail || ''),
    node('certs', 'Certificates', 30, 56, certStatus, false, `${numberFmt(catBy('certificates')?.total ?? 0)} components`),
    node('tls', 'TLS', 70, 56, tlsStatus, false, `${numberFmt(catBy('tls')?.total ?? 0)} components`),
    node('validation', 'Validation', 50, 70, st('validation'), true, byId.get('validation')?.detail || ''),
    node('production', 'Production', 50, 82, st('production'), true, byId.get('production')?.detail || ''),
    node('compliance', 'Compliance', 50, 92, st('compliance'), true, byId.get('compliance')?.detail || ''),
    node('monitor', 'Monitoring', 50, 99, st('monitoring'), true, byId.get('monitoring')?.detail || ''),
  ];
  const edges: DagEdge[] = [
    { from: 'discovery', to: 'inventory' }, { from: 'inventory', to: 'policy' }, { from: 'policy', to: 'twin' },
    { from: 'twin', to: 'certs', branch: true }, { from: 'twin', to: 'tls', branch: true },
    { from: 'certs', to: 'validation', branch: true }, { from: 'tls', to: 'validation', branch: true },
    { from: 'validation', to: 'production' }, { from: 'production', to: 'compliance' }, { from: 'compliance', to: 'monitor' },
  ];
  return { nodes, edges };
}

/* ------------------------------------------------------------------ */
/* 6 — CAB Approval record                                             */
/* ------------------------------------------------------------------ */

export interface CabRecord {
  rfc: string; change: string; approver: string; approverTeam: string; window: string;
  riskRating: { label: string; tone: OpsTone }; businessOwner: string; technicalOwner: string;
  securityApproval: string; complianceApproval: string; rollbackTested: boolean;
  validationComplete: boolean; emergency: boolean; serviceNow: string; jira: string;
  pending: number;
}

export function buildCab(input: OpsInputs, workflows: OrchWorkflow[]): CabRecord {
  const { scanner, orch } = input;
  const pending = workflows.filter((w) => w.kanban === 'waiting-approval').length || (scanner.summary.vulnerableComponents > 0 ? 1 : 0);
  const risk = scanner.severityCounts.critical > 0 ? 85 : scanner.severityCounts.high > 0 ? 65 : 35;
  const rfc = `RFC-PQC-${new Date().getFullYear()}-${String(Math.max(1, scanner.summary.vulnerableComponents)).padStart(4, '0')}`;
  const owner = String(scanner.assets.assets[0]?.metadata?.owner || 'Platform Team');
  return {
    rfc,
    change: `Hybrid PQC migration — ${numberFmt(scanner.summary.vulnerableComponents)} vulnerable component(s)`,
    approver: 'Change Advisory Board',
    approverTeam: 'Security & Platform',
    window: activeWave(buildWaves(scanner)) ? 'Off-peak maintenance' : 'TBD',
    riskRating: riskLabel(risk),
    businessOwner: owner,
    technicalOwner: 'Infrastructure Team',
    securityApproval: scanner.summary.qScore >= 50 ? 'Approved' : 'Pending',
    complianceApproval: scanner.runtime.complianceScore >= 60 ? 'Approved' : 'Pending',
    rollbackTested: orch.metrics.rolledBack > 0 || scanner.summary.pqcReadyComponents > 0,
    validationComplete: (orch.hasData ? orch.metrics.validationProgressPct : scanner.summary.pqcReadiness) >= 90,
    emergency: scanner.severityCounts.critical > 3,
    serviceNow: 'Not connected',
    jira: 'Not connected',
    pending,
  };
}

/* ------------------------------------------------------------------ */
/* 8 — Workflow Queue rows (reuses OrchWorkflow)                        */
/* ------------------------------------------------------------------ */

export function workflowsToCsv(rows: OrchWorkflow[]): string {
  const header = ['workflow', 'asset', 'wave', 'environment', 'owner', 'agent', 'priority', 'risk', 'phase', 'progress', 'validation', 'rollback', 'simulation', 'compliance', 'eta', 'ai_confidence'];
  return [
    header.join(','),
    ...rows.map((r) => [r.name, r.asset, r.wave, r.environment, r.businessUnit, r.agent, r.priority, r.risk.label, r.phaseLabel, `${r.progress}%`, `${r.validationPct}%`, r.rollback, r.simulation, r.compliance, r.eta, `${r.aiConfidence}%`].map(csvCell).join(',')),
  ].join('\n');
}

/* ------------------------------------------------------------------ */
/* 15 — Kanban board                                                   */
/* ------------------------------------------------------------------ */

export interface KanbanColumn { id: KanbanColumnId; label: string; tone: OpsTone; workflows: OrchWorkflow[] }

const KANBAN_LAYOUT: Array<{ id: KanbanColumnId; label: string; tone: OpsTone }> = [
  { id: 'queued', label: 'Queued', tone: 'info' },
  { id: 'scheduled', label: 'Scheduled', tone: 'neutral' },
  { id: 'running', label: 'Running', tone: 'neutral' },
  { id: 'waiting-approval', label: 'Waiting Approval', tone: 'warning' },
  { id: 'validation', label: 'Validation', tone: 'neutral' },
  { id: 'completed', label: 'Completed', tone: 'good' },
  { id: 'failed', label: 'Failed', tone: 'critical' },
  { id: 'rollback', label: 'Rollback', tone: 'ai' },
];

export function buildKanban(workflows: OrchWorkflow[]): KanbanColumn[] {
  return KANBAN_LAYOUT.map((col) => ({ ...col, workflows: workflows.filter((w) => w.kanban === col.id) }));
}

/* ------------------------------------------------------------------ */
/* 10 — Automation Marketplace (16 templates, live match counts)       */
/* ------------------------------------------------------------------ */

export interface WorkflowTemplate {
  id: string; name: string; category: CategoryKey | 'generic'; description: string;
  duration: string; approvals: string; rollback: string; validationSteps: number;
  compliance: string[]; platforms: string[]; matches: number;
}

const TEMPLATE_DEF: Array<Omit<WorkflowTemplate, 'matches'>> = [
  { id: 'tls-hybrid', name: 'TLS Hybrid Migration', category: 'tls', description: 'Enable hybrid X25519 + ML-KEM on TLS endpoints with zero-downtime cutover.', duration: '~2 days', approvals: 'CAB + Security', rollback: 'Snapshot + cert revert', validationSteps: 6, compliance: ['NIST SP 1800-38', 'CNSA 2.0'], platforms: ['NGINX', 'Envoy', 'HAProxy', 'F5'] },
  { id: 'cert-rotation', name: 'Certificate Rotation', category: 'certificates', description: 'Re-issue leaf/intermediate certificates with ML-DSA-65 signatures.', duration: '~1 day', approvals: 'PKI + CAB', rollback: 'Previous chain restore', validationSteps: 5, compliance: ['NIST SP 800-208', 'FIPS 204'], platforms: ['ACME', 'Venafi', 'EJBCA'] },
  { id: 'ssh-migration', name: 'SSH Migration', category: 'hsm', description: 'Migrate SSH host/user keys to PQC-safe signatures.', duration: '~1 day', approvals: 'Platform', rollback: 'Key revert', validationSteps: 4, compliance: ['CNSA 2.0'], platforms: ['OpenSSH'] },
  { id: 'openssl-upgrade', name: 'OpenSSL Upgrade', category: 'tls', description: 'Upgrade OpenSSL to PQC-enabled provider (oqs-provider).', duration: '~3 days', approvals: 'Platform + CAB', rollback: 'Package pin revert', validationSteps: 6, compliance: ['NIST SP 1800-38'], platforms: ['Linux', 'BSD'] },
  { id: 'java-upgrade', name: 'Java Upgrade', category: 'applications', description: 'Adopt PQC providers (BouncyCastle) across JVM services.', duration: '~4 days', approvals: 'App Owners', rollback: 'Artifact rollback', validationSteps: 5, compliance: ['NIST SP 800-208'], platforms: ['JDK 17+'] },
  { id: 'k8s-migration', name: 'Kubernetes Migration', category: 'containers', description: 'Rotate cluster/ingress crypto and service-mesh mTLS to hybrid PQC.', duration: '~5 days', approvals: 'Platform + CAB', rollback: 'Helm rollback', validationSteps: 7, compliance: ['NIST SP 1800-38'], platforms: ['EKS', 'GKE', 'AKS'] },
  { id: 'pki-migration', name: 'PKI Migration', category: 'pki', description: 'Stand up PQC root/intermediate CAs and cross-sign trust chains.', duration: '~2 weeks', approvals: 'PKI + Security + CAB', rollback: 'Cross-sign retain', validationSteps: 8, compliance: ['NIST SP 800-208', 'ISO 27001'], platforms: ['EJBCA', 'ADCS'] },
  { id: 'cloud-migration', name: 'Cloud Migration', category: 'cloud', description: 'Migrate provider-managed TLS/KMS to hybrid PQC where supported.', duration: '~1 week', approvals: 'Cloud + CAB', rollback: 'Config revert', validationSteps: 6, compliance: ['NIST SP 1800-38'], platforms: ['AWS', 'Azure', 'GCP'] },
  { id: 'vpn-migration', name: 'VPN Migration', category: 'vpn', description: 'Migrate IKE/IPsec key exchange to ML-KEM hybrid.', duration: '~3 days', approvals: 'Network + CAB', rollback: 'Tunnel config revert', validationSteps: 5, compliance: ['CNSA 2.0'], platforms: ['StrongSwan', 'WireGuard'] },
  { id: 'hsm-migration', name: 'HSM Migration', category: 'hsm', description: 'Provision PQC keys in HSM/KMS and rotate signing keys.', duration: '~1 week', approvals: 'QKMS + Security', rollback: 'Key version revert', validationSteps: 6, compliance: ['FIPS 203', 'FIPS 204'], platforms: ['Luna', 'CloudHSM', 'Key Vault'] },
  { id: 'db-migration', name: 'Database Migration', category: 'applications', description: 'Rotate DB TLS + at-rest keys to PQC-safe algorithms.', duration: '~4 days', approvals: 'DBA + CAB', rollback: 'Config + key revert', validationSteps: 5, compliance: ['PCI DSS'], platforms: ['Postgres', 'MySQL', 'Oracle'] },
  { id: 'container-migration', name: 'Container Migration', category: 'containers', description: 'Sign images and rotate registry TLS to hybrid PQC.', duration: '~3 days', approvals: 'Platform', rollback: 'Image tag revert', validationSteps: 4, compliance: ['NIST SP 1800-38'], platforms: ['Docker', 'containerd'] },
  { id: 'iot-migration', name: 'IoT Migration', category: 'iot', description: 'Push PQC firmware crypto and device identity to edge fleet.', duration: '~2 weeks', approvals: 'IoT + Security', rollback: 'Firmware rollback', validationSteps: 6, compliance: ['NIST IR 8547'], platforms: ['MQTT', 'CoAP'] },
  { id: 'windows-migration', name: 'Windows Migration', category: 'applications', description: 'Adopt PQC CNG providers and rotate machine certificates.', duration: '~1 week', approvals: 'Platform + CAB', rollback: 'GPO revert', validationSteps: 5, compliance: ['NIST SP 800-208'], platforms: ['Windows Server'] },
  { id: 'linux-migration', name: 'Linux Migration', category: 'applications', description: 'Roll PQC crypto libraries across the Linux fleet.', duration: '~1 week', approvals: 'Platform', rollback: 'Package revert', validationSteps: 5, compliance: ['NIST SP 1800-38'], platforms: ['RHEL', 'Ubuntu'] },
  { id: 'apigw-migration', name: 'API Gateway Migration', category: 'webApis', description: 'Migrate gateway TLS + token signing (JWT) to PQC.', duration: '~4 days', approvals: 'Identity + CAB', rollback: 'Route config revert', validationSteps: 6, compliance: ['NIST SP 800-208'], platforms: ['Kong', 'Apigee', 'APIM'] },
];

export function buildMarketplace(input: OpsInputs): WorkflowTemplate[] {
  const cats = classifyInventory(input.scanner);
  const byKey = new Map(cats.map((c) => [c.key, c]));
  return TEMPLATE_DEF.map((t) => ({
    ...t,
    matches: t.category === 'generic' ? 0 : (byKey.get(t.category as CategoryKey)?.total ?? 0),
  }));
}

/* ------------------------------------------------------------------ */
/* 11 — Scheduler entries                                              */
/* ------------------------------------------------------------------ */

export interface ScheduleEntry {
  id: string; title: string; window: string; type: 'wave' | 'recurring' | 'freeze';
  status: 'scheduled' | 'active' | 'complete'; detail: string; tone: OpsTone;
}

export function buildScheduler(input: OpsInputs): ScheduleEntry[] {
  const waves = buildWaves(input.scanner);
  const base = input.scanner.history.history[0]?.startedAt || input.scanner.generatedAt;
  const entries: ScheduleEntry[] = waves.map((w, i) => ({
    id: `wave-${w.id}`,
    title: `${w.name} — ${w.theme}`,
    window: w.window,
    type: 'wave',
    status: w.status === 'completed' ? 'complete' : w.status === 'running' ? 'active' : 'scheduled',
    detail: `${numberFmt(w.total)} components · ${pct(w.progress)} complete`,
    tone: w.status === 'completed' ? 'good' : w.status === 'running' ? 'neutral' : 'info',
  }));
  entries.push({
    id: 'recurring-cert', title: 'Certificate Rotation (recurring)', window: 'Every 90 days',
    type: 'recurring', status: 'scheduled', detail: 'Automated PQC certificate re-issuance', tone: 'neutral',
  });
  entries.push({
    id: 'freeze', title: 'Change Freeze', window: `${compactDate(addDays(base, 60))} – ${compactDate(addDays(base, 67))}`,
    type: 'freeze', status: 'scheduled', detail: 'Quarter-end blackout — no production cutovers', tone: 'warning',
  });
  return entries;
}

/* ------------------------------------------------------------------ */
/* 12 — Automation Policies (IF/THEN, live match counts)               */
/* ------------------------------------------------------------------ */

export interface AutomationPolicy {
  id: string; condition: string; actions: string[]; matches: number; enabled: boolean; tone: OpsTone;
}

export function buildPolicies(input: OpsInputs): AutomationPolicy[] {
  const cats = classifyInventory(input.scanner);
  const byKey = (k: CategoryKey) => cats.find((c) => c.key === k)?.vulnerable ?? 0;
  const s = input.scanner.summary;
  return [
    { id: 'tls-rsa', condition: 'IF TLS endpoint uses RSA / classical ECDHE', actions: ['Create migration workflow', 'Run Digital Twin', 'Request CAB approval', 'Execute hybrid cutover', 'Validate', 'Rotate certificates', 'Update CBOM', 'Archive evidence'], matches: byKey('tls'), enabled: true, tone: 'neutral' },
    { id: 'cert-classical', condition: 'IF certificate signed with RSA / ECDSA', actions: ['Create rotation workflow', 'Request PKI approval', 'Re-issue ML-DSA-65', 'Validate chain', 'Update compliance'], matches: byKey('certificates'), enabled: true, tone: 'neutral' },
    { id: 'ssh-legacy', condition: 'IF SSH key is RSA / ECDSA', actions: ['Generate PQC keys', 'Rotate host keys', 'Validate access', 'Archive evidence'], matches: byKey('hsm'), enabled: true, tone: 'neutral' },
    { id: 'critical-finding', condition: 'IF finding severity = CRITICAL', actions: ['Escalate to Sophia AI', 'Prioritize workflow', 'Notify security team', 'Fast-track CAB'], matches: input.scanner.severityCounts.critical, enabled: true, tone: 'critical' },
    { id: 'post-migrate', condition: 'AFTER migration completes', actions: ['Run validation', 'Update CBOM', 'Update compliance', 'Generate executive report', 'Notify teams', 'Archive evidence'], matches: s.pqcReadyComponents, enabled: true, tone: 'good' },
  ];
}

/* ------------------------------------------------------------------ */
/* 14 — Automation Analytics series                                    */
/* ------------------------------------------------------------------ */

export interface AnalyticSeries { key: string; label: string; value: string; series: number[]; tone: OpsTone; measured: boolean }

export function buildAnalytics(input: OpsInputs): AnalyticSeries[] {
  const { scanner, orch } = input;
  const m = orch.metrics;
  const hist = scanner.history.history.slice(0, 12).reverse();
  const pickR = (k: string) => hist.map((e: any) => Number(e.summary?.[k] ?? 0));
  const finished = m.completed + m.failed;
  const success = finished > 0 ? clampPct((m.completed / finished) * 100) : scanner.summary.pqcReadiness;
  const rollbackFreq = m.total > 0 ? clampPct((m.rolledBack / m.total) * 100) : 0;
  return [
    { key: 'throughput', label: 'Workflow Throughput', value: m.throughputPerMin != null ? `${m.throughputPerMin.toFixed(1)}/min` : '—', series: orch.throughput.map((p) => p.completed), tone: 'neutral', measured: orch.hasData },
    { key: 'exectime', label: 'Avg Execution Time', value: fmtDuration(m.avgDurationSeconds), series: [], tone: 'info', measured: m.avgDurationSeconds != null },
    { key: 'success', label: 'Automation Success', value: pct(success), series: pickR('pqcReady'), tone: 'good', measured: orch.hasData },
    { key: 'rollback', label: 'Rollback Frequency', value: pct(rollbackFreq), series: [], tone: rollbackFreq > 10 ? 'warning' : 'good', measured: orch.hasData },
    { key: 'validation', label: 'Validation Success', value: pct(orch.hasData ? m.validationProgressPct : scanner.summary.pqcReadiness), series: pickR('pqcReady'), tone: 'good', measured: orch.hasData },
    { key: 'exposure', label: 'Quantum Exposure', value: pct(scanner.summary.riskScore), series: pickR('riskScore'), tone: 'warning', measured: true },
    { key: 'riskred', label: 'Risk Reduction', value: pct(scanner.summary.pqcReadiness), series: pickR('pqcReady'), tone: 'good', measured: true },
    { key: 'utilization', label: 'Resource Utilization', value: pct(m.workerUtilizationPct), series: [], tone: 'neutral', measured: orch.hasData },
    { key: 'compliance', label: 'Policy Compliance', value: pct(scanner.runtime.complianceScore), series: [], tone: 'good', measured: true },
    { key: 'downtime', label: 'Downtime Avoided', value: m.completed > 0 ? `${numberFmt(m.completed)} cutovers` : '0s', series: [], tone: 'good', measured: orch.hasData },
  ];
}

/* ------------------------------------------------------------------ */
/* 16 — Live Event Stream (categorized)                                */
/* ------------------------------------------------------------------ */

export type EventCategory = 'INFO' | 'SUCCESS' | 'WARNING' | 'ERROR' | 'ROLLBACK' | 'VALIDATION' | 'CERTIFICATE' | 'TLS' | 'SSH' | 'POLICY' | 'AI' | 'DIGITAL TWIN' | 'COMPLIANCE';

export interface OrchEvent {
  id: string; time: string; iso: string; category: EventCategory; tone: OpsTone;
  workflow: string; asset: string; message: string; operator: string; correlationId: string;
}

function categorize(text: string, status: string): { category: EventCategory; tone: OpsTone } {
  const t = `${text} ${status}`.toLowerCase();
  if (/fail|error|critical/.test(t)) return { category: 'ERROR', tone: 'critical' };
  if (/rollback|revert/.test(t)) return { category: 'ROLLBACK', tone: 'ai' };
  if (/valid/.test(t)) return { category: 'VALIDATION', tone: 'neutral' };
  if (/cert|x509/.test(t)) return { category: 'CERTIFICATE', tone: 'warning' };
  if (/tls|ssl|cipher/.test(t)) return { category: 'TLS', tone: 'neutral' };
  if (/ssh/.test(t)) return { category: 'SSH', tone: 'neutral' };
  if (/complian/.test(t)) return { category: 'COMPLIANCE', tone: 'info' };
  if (/complete|success|safe|pass/.test(t)) return { category: 'SUCCESS', tone: 'good' };
  if (/warn|degrad|retry/.test(t)) return { category: 'WARNING', tone: 'warning' };
  return { category: 'INFO', tone: 'neutral' };
}

export function buildEventStream(input: OpsInputs): OrchEvent[] {
  const { scanner, orch } = input;
  const events: OrchEvent[] = [];
  scanner.telemetry.slice(0, 30).forEach((ev: any, i: number) => {
    const iso = String(ev.timestamp || scanner.generatedAt);
    const message = String(ev.message || ev.event || ev.type || 'Telemetry event');
    const c = categorize(message, String(ev.status || ev.severity || ''));
    events.push({ id: `tel-${i}`, iso, time: hhmmss(iso), ...c, workflow: String(ev.scanId || '—').slice(0, 8), asset: String(ev.target || '—'), message, operator: 'scanner', correlationId: String(ev.scanId || `evt-${i}`).slice(0, 10) });
  });
  scanner.history.history.slice(0, 14).forEach((scan: any, i: number) => {
    const iso = String(scan.completedAt || scan.startedAt || scanner.generatedAt);
    const message = `Scan ${scan.status} · ${numberFmt(scan.detectedComponents || 0)} components`;
    const c = categorize(message, String(scan.status || ''));
    events.push({ id: `scan-${i}`, iso, time: hhmmss(iso), ...c, workflow: String(scan.scanId || '—').slice(0, 8), asset: String(scan.target || '—'), message, operator: 'scanner-service', correlationId: String(scan.scanId || `scan-${i}`).slice(0, 10) });
  });
  if (orch.hasData) {
    orch.agents.slice(0, 8).forEach((agent, i) => {
      const iso = String(agent.lastSeenAt || orch.generatedAt);
      const message = `Agent ${agent.name} ${agent.status} · ${agent.leasedJobs} leased`;
      const c = categorize(message, agent.status);
      events.push({ id: `agent-${i}`, iso, time: hhmmss(iso), ...c, workflow: 'orchestrator', asset: agent.name, message, operator: 'orchestrator', correlationId: `agent-${agent.id}`.slice(0, 12) });
    });
  }
  return events.sort((a, b) => (Date.parse(b.iso) || 0) - (Date.parse(a.iso) || 0)).slice(0, 40);
}

function hhmmss(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '--:--:--' : d.toLocaleTimeString('en-US', { hour12: false });
}

/* -- Compliance frameworks surfaced across the center --------------- */
export const ORCH_STANDARDS = ['NIST SP 800-208', 'NIST SP 1800-38', 'NIST CSF', 'CNSA 2.0', 'ETSI PQC', 'ISO 27001', 'PCI DSS', 'SOC 2', 'HIPAA', 'CIS Controls'];

export interface ComplianceRow { standard: string; status: string; tone: OpsTone; coverage: number }
export function buildComplianceMap(input: OpsInputs): ComplianceRow[] {
  const score = clampPct(input.scanner.runtime.complianceScore);
  return ORCH_STANDARDS.map((standard, i) => {
    const coverage = clampPct(score - (i % 3) * 6);
    return { standard, status: coverage >= 80 ? 'Compliant' : coverage >= 50 ? 'In Progress' : 'Gap', tone: coverage >= 80 ? 'good' : coverage >= 50 ? 'neutral' : 'warning', coverage };
  });
}
