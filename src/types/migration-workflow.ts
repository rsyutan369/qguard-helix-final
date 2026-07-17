/**
 * Post-Quantum Migration Workflow™ — shared frontend/backend contract.
 *
 * Models the entire platform as ONE state-driven lifecycle instead of a
 * collection of independent dashboards. Every stage status is derived from the
 * same live evidence the individual modules display (scanner intelligence,
 * CBOM, Q-REMEDY remediation plan, migration plans/jobs/validation logs,
 * quantum trust certificates) so status indicators can never disagree between
 * pages.
 */

export type WorkflowStageId =
  | 'discovery'
  | 'cbom'
  | 'assessment'
  | 'risk'
  | 'remediation'
  | 'planning'
  | 'approval'
  | 'execution'
  | 'validation'
  | 'monitoring'
  | 'certification';

export type WorkflowStageStatus = 'complete' | 'active' | 'pending' | 'blocked';

export interface WorkflowStage {
  id: WorkflowStageId;
  label: string;
  shortLabel: string;
  status: WorkflowStageStatus;
  progressPct: number;
  kpi: string; // headline number for the stage ("412 assets", "7 open actions")
  detail: string; // one-line evidence basis
  route: string; // module that owns this stage
}

export interface WorkflowNextAction {
  stageId: WorkflowStageId;
  title: string;
  detail: string;
  route: string;
}

/** Per-asset lifecycle position (bounded list, highest risk first). */
export interface WorkflowAssetState {
  asset: string;
  stageId: WorkflowStageId;
  stageLabel: string;
  riskScore: number;
  openActions: number;
  migrationStatus: 'none' | 'planned' | 'running' | 'completed';
  validationStatus: string;
  certificationImpactPct: number;
}

export interface MigrationWorkflowState {
  generatedAt: string;
  hasData: boolean;
  overallProgressPct: number;
  currentStageId: WorkflowStageId;
  stages: WorkflowStage[];
  nextAction: WorkflowNextAction;
  certificationReadinessPct: number;
  certificationEligible: boolean;
  assetLifecycle: Array<{ stageId: WorkflowStageId; label: string; count: number }>;
  assetStates: WorkflowAssetState[];
}
