/**
 * Intelligent Quantum Remediation Engine™ — shared frontend/backend contract.
 *
 * Every value is evidence-driven: remediation actions are synthesized from the
 * live scanner findings, CBOM, certificate inventory and dependency graph the
 * platform has actually observed — never invented. The Certification Readiness
 * Score is a continuous 0–100% measure of progress across the SAME 10 required
 * criteria the Quantum Trust Certification Engine™ enforces (100% == eligible),
 * and every projected score is produced by the deterministic Q-REMEDY
 * marginal-gain simulation whose methodology ships with the payload.
 */

import type { EligibilityCheck, EligibilityResult } from './quantum-certification';

export type { EligibilityCheck, EligibilityResult };

export type RemediationDomain =
  | 'tls'
  | 'ssh'
  | 'vpn'
  | 'pki'
  | 'key-management'
  | 'application'
  | 'cloud'
  | 'data-at-rest'
  | 'identity'
  | 'vendor'
  | 'inventory';

export type RemediationPriority = 'critical' | 'high' | 'medium' | 'low';
export type RemediationEffort = 'low' | 'medium' | 'high';
export type RemediationStatus = 'open' | 'in_progress' | 'resolved';

/** One measured reason an asset is not quantum-ready. */
export interface RemediationFindingRef {
  id: string;
  algorithm: string;
  category: string;
  severity: string;
  description: string;
  instances: number;
}

/** Which assets/trust relationships are affected if this asset is migrated. */
export interface BlastRadius {
  dependents: string[]; // assets that depend on this asset (may break)
  dependencies: string[]; // assets this asset depends on (sequence first)
  vendorParties: string[]; // third-party / supply-chain parties involved
  degree: number; // total relationship degree (0 when no graph evidence)
}

/** The measured deltas applying this action has on the certification criteria. */
export interface RemediationImpact {
  criticalResolved: number;
  highResolved: number;
  mediumResolved: number;
  lowResolved: number;
  vulnerableComponentsResolved: number;
  pqcComponentsAdded: number;
  disallowedAlgorithmsRetired: string[];
  expiredCertificatesRenewed: number;
  evidenceSourcesConnected: string[]; // for confidence/validation gap actions
  confidenceGainPct: number; // projected assessment-confidence gain (evidence actions)
  hndlReductionPts: number; // extra HNDL reduction beyond the vulnerable-share model
  validationRepair: boolean; // action projected to restore report self-validation PASS
  runtimeTelemetryConnected: boolean; // action connects runtime crypto telemetry
}

/** A single asset-level remediation action — the heart of the engine. */
export interface RemediationAction {
  id: string;
  rank: number; // 1-based position in the Q-REMEDY execution order
  asset: string;
  assetType: string;
  environment: string;
  owner: string;
  internetFacing: boolean;
  criticality: string;
  domain: RemediationDomain;
  domainLabel: string;
  problem: string; // "TLS uses RSA-2048"
  risk: string; // "Harvest Now, Decrypt Later"
  whyNotReady: string[]; // measured reasons, evidence-grounded
  findings: RemediationFindingRef[];
  recommendation: string; // headline fix
  steps: string[]; // playbook steps (NIST/CNSA-aligned)
  currentState: string;
  targetState: string; // e.g. "Hybrid X25519 + ML-KEM-768 (FIPS 203)"
  standards: string[]; // e.g. ["FIPS 203", "CNSA 2.0"]
  priority: RemediationPriority;
  priorityScore: number; // 0–100 composite
  priorityBreakdown: Array<{ factor: string; score: number; weightPct: number }>;
  effort: RemediationEffort;
  effortWeeks: number;
  estimatedDowntime: string;
  rollback: string;
  breakingChangeWarning: string | null;
  blastRadius: BlastRadius;
  requiresReplacement: boolean; // system cannot support PQC → replace
  automatable: boolean;
  status: RemediationStatus;
  statusEvidence: string; // why the engine believes this status
  impact: RemediationImpact;
  certificationGainPct: number; // marginal Certification Readiness gain
  projectedReadinessPct: number; // cumulative score after this action (ladder)
  criteriaAddressed: string[]; // eligibility check ids this action moves
  integration: { label: string; route: string }; // deep link into the platform
  quickWin: boolean;
}

/** Continuous progress on one certification criterion. */
export interface CriterionProgress {
  id: string;
  criterion: string;
  required: string;
  actual: string;
  met: boolean;
  progressPct: number; // 0–100 continuous progress toward the threshold
  weightPct: number;
  evidence: string;
}

/** One rung of the readiness projection ladder. */
export interface ReadinessLadderStep {
  stage: string; // "Current Readiness" | "After Recommendation #1" | ...
  actionId: string | null;
  actionTitle: string;
  readinessPct: number;
  gainPct: number;
  effortWeeks: number;
  detail: string;
}

/** An unmet certification requirement, enriched per the remediation spec. */
export interface CertificationRequirementGap {
  id: string;
  requirement: string;
  status: 'unmet' | 'met';
  severity: 'required' | 'advisory';
  description: string;
  businessImpact: string;
  technicalImpact: string;
  recommendedSolution: string;
  relatedAssets: string[];
  relatedActionIds: string[];
  estimatedCompletionWeeks: number;
  estimatedScoreIncreasePct: number;
  integration: { label: string; route: string };
}

/** Deterministic AI Quantum Advisor™ Q&A synthesized from the plan. */
export interface AdvisorAnswer {
  question: string;
  answer: string;
  evidence: string[];
  route: string | null;
}

export interface RemediationProgress {
  totalActions: number;
  openActions: number;
  inProgressActions: number;
  resolvedActions: number;
  completionPct: number;
  migrationJobsCompleted: number;
  migrationJobsRunning: number;
  recentlyFixed: Array<{ title: string; detail: string; completedAt: string | null; source: string }>;
  upcomingTasks: Array<{ actionId: string; title: string; priority: RemediationPriority; effortWeeks: number }>;
}

export interface RemediationMethodology {
  name: string;
  version: string;
  summary: string;
  scoreFormula: string;
  priorityFactors: Array<{ factor: string; weightPct: number; basis: string }>;
  simulation: string;
  honesty: string;
}

/** Full payload served by GET /api/v1/quantum-remediation. */
export interface RemediationPlan {
  generatedAt: string;
  hasData: boolean;
  // Live Certification Readiness Score™
  certificationReadinessPct: number;
  certificationEligible: boolean;
  trustScore: number;
  levelLabel: string;
  requiredMet: number;
  requiredTotal: number;
  quantumReadiness: number;
  quantumRisk: number;
  hndlRisk: number;
  pqcAdoption: number;
  estimatedCertificationDate: string | null;
  estimatedCompletionWeeks: number;
  parallelWorkstreams: number;
  // Engine output
  criteria: CriterionProgress[];
  requirements: CertificationRequirementGap[];
  actions: RemediationAction[];
  ladder: ReadinessLadderStep[];
  queues: Record<RemediationPriority, number>;
  quickWins: string[]; // action ids
  criticalBlockers: string[]; // action ids
  vendorActions: string[]; // action ids flagged with third-party impact
  replacementsRequired: string[]; // action ids where migration is impossible
  advisor: AdvisorAnswer[];
  progress: RemediationProgress;
  assetsByRisk: Array<{ label: string; count: number }>;
  remainingVulnerabilities: { critical: number; high: number; medium: number; low: number; total: number };
  readinessTrend: Array<{ label: string; readiness: number; risk: number }>;
  methodology: RemediationMethodology;
}
