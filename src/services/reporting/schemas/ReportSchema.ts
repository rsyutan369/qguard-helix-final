import { z } from 'zod';

/**
 * QGuard Helix Enterprise Reporting Engine™ — unified report model.
 *
 * `EnterpriseAssessmentReport` is the single source of truth every exporter
 * (PDF / DOCX / XLSX / CSV / JSON / HTML / PPTX) consumes. It is assembled
 * exclusively from real assessment evidence/telemetry — see ReportEvidence.ts.
 * Missing evidence is represented explicitly (`Evidence Not Available`); findings
 * are never fabricated.
 */

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const REPORT_KINDS = ['executive', 'technical', 'compliance', 'migration'] as const;
export type ReportKind = (typeof REPORT_KINDS)[number];

export const REPORT_FORMATS = ['pdf', 'docx', 'xlsx', 'csv', 'json', 'html', 'pptx'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

export const EVIDENCE_UNAVAILABLE = 'Evidence Not Available';

export const findingSchema = z.object({
  id: z.string(),
  title: z.string(),
  severity: z.enum(SEVERITIES),
  evidence: z.string(),
  affectedAssets: z.array(z.string()),
  recommendation: z.string(),
  remediationPlan: z.string(),
  source: z.string().default('QGuard Helix'),
  detectedAt: z.string().nullable().optional(),
  // Actionable enrichment (Enhancement #1)
  currentState: z.string().default(EVIDENCE_UNAVAILABLE),
  recommendedState: z.string().default(EVIDENCE_UNAVAILABLE),
  businessImpact: z.string().default(EVIDENCE_UNAVAILABLE),
  technicalImpact: z.string().default(EVIDENCE_UNAVAILABLE),
  migrationComplexity: z.enum(['Low', 'Medium', 'High']).default('Medium'),
  dependencies: z.array(z.string()).default([]),
  owner: z.string().default('Security Engineering'),
  targetDate: z.string().default(EVIDENCE_UNAVAILABLE),
  validation: z.string().default(EVIDENCE_UNAVAILABLE),
  riskReductionPct: z.number().default(0),
  estimatedCostUsd: z.number().default(0),
  estimatedEffort: z.string().default(EVIDENCE_UNAVAILABLE),
});
export type ReportFinding = z.infer<typeof findingSchema>;

/* ---- Board-level program sections (Report Enhancement 1 & 2) ---- */

// I2#8 — Top Business Risks (board language, evidence-driven)
export const businessRiskSchema = z.object({ risk: z.string(), level: z.string(), driver: z.string() });
export type BusinessRisk = z.infer<typeof businessRiskSchema>;

export const executiveBlockSchema = z.object({
  currentReadiness: z.number(),
  targetReadiness: z.number(),
  currentRisk: z.number(),
  targetRisk: z.number(),
  currentHndl: z.number(),
  targetHndl: z.number(),
  estimatedDurationWeeks: z.number(),
  estimatedCostUsd: z.number(),
  expectedRiskReductionPct: z.number(),
  expectedComplianceImprovementPct: z.number(),
  quantumExposureWindow: z.string(),
  topRisks: z.array(z.string()),
  topActions: z.array(z.string()),
  // I2#8 — board-language business risks (Internet-facing TLS, HNDL, …)
  topBusinessRisks: z.array(businessRiskSchema).default([]),
  executiveRecommendation: z.string(),
});
export type ExecutiveBlock = z.infer<typeof executiveBlockSchema>;

export const businessImpactSchema = z.object({
  customerFacingSystems: z.number(),
  missionCriticalSystems: z.number(),
  revenueImpact: z.string(),
  operationalImpact: z.string(),
  complianceImpact: z.string(),
  reputationalImpact: z.string(),
  financialImpact: z.string(),
  thirdPartyDependencies: z.number(),
  hndlExposure: z.string(),
  quantumExposureWindow: z.string(),
});
export type BusinessImpact = z.infer<typeof businessImpactSchema>;

export const readinessDomainSchema = z.object({
  domain: z.string(),
  score: z.number(),
  targetScore: z.number().default(0),
  targetRationale: z.string().default(EVIDENCE_UNAVAILABLE),
  riskLevel: z.string(),
  owner: z.string(),
  actions: z.string(),
});
export type ReadinessDomain = z.infer<typeof readinessDomainSchema>;

export const migrationAdvisorSchema = z.object({
  recommendation: z.string(),
  reason: z.string(),
  affectedAssets: z.array(z.string()),
  riskReductionPct: z.number(),
  costUsd: z.number(),
  timelineWeeks: z.number(),
  complexity: z.string(),
  successProbabilityPct: z.number(),
  confidencePct: z.number(),
});
export type MigrationAdvisor = z.infer<typeof migrationAdvisorSchema>;

export const migrationWaveSchema = z.object({
  wave: z.number(),
  name: z.string(),
  assets: z.array(z.string()),
  owner: z.string(),
  durationWeeks: z.number(),
  costUsd: z.number(),
  dependencies: z.array(z.string()),
  riskReductionPct: z.number(),
  status: z.string(),
  priority: z.string(),
});
export type MigrationWave = z.infer<typeof migrationWaveSchema>;

export const playbookStageSchema = z.object({
  wave: z.string(),
  prerequisites: z.string(),
  preparation: z.string(),
  execution: z.string(),
  rollback: z.string(),
  validation: z.string(),
  successCriteria: z.string(),
});
export type PlaybookStage = z.infer<typeof playbookStageSchema>;

export const riskCategorySchema = z.object({
  category: z.string(),
  currentScore: z.number(),
  targetScore: z.number(),
  reductionPotentialPct: z.number(),
});
export type RiskCategory = z.infer<typeof riskCategorySchema>;

export const hndlCategorySchema = z.object({
  category: z.string(),
  retention: z.string(),
  currentProtection: z.string(),
  hndlRisk: z.string(),
  recommendedProtection: z.string(),
});
export type HndlCategory = z.infer<typeof hndlCategorySchema>;

export const costLineSchema = z.object({ category: z.string(), costUsd: z.number() });
export const costExclusionSchema = z.object({
  category: z.string(),
  reason: z.string(),
  route: z.string().optional(),
});
export const budgetVarianceSchema = z.object({
  budgetUsd: z.number(),
  estimateUsd: z.number(),
  varianceUsd: z.number(),
  variancePct: z.number(),
  status: z.enum(['within-budget', 'over-budget']),
});
export const costForecastSchema = z.object({
  lines: z.array(costLineSchema),
  totalUsd: z.number(),
  projectedRiskReductionValueUsd: z.number(),
  /** Categories the evidence does not support, so they were NOT costed. */
  excludedCategories: z.array(costExclusionSchema).default([]),
  /** The planning assumptions behind every figure — always published with them. */
  assumptions: z.string().default(''),
  blendedRateUsd: z.number().default(0),
  hoursPerWeek: z.number().default(0),
  totalHours: z.number().default(0),
  /** How the risk-reduction value was derived (never a bare multiple of cost). */
  valueBasis: z.string().default(''),
  financialExposureUsd: z.number().default(0),
  /** Present only when the tenant supplied their own budget. */
  budget: budgetVarianceSchema.nullable().default(null),
});
export type CostForecast = z.infer<typeof costForecastSchema>;

// I3#7 — Risk-trend scenario band. Free-form label: scenarios are anchored to
// the programme schedule (e.g. "Funded Programme (Expected)", "No Funded
// Programme (Baseline)") — a fixed Best/Expected/Worst enum can't express them,
// and older reports' labels remain valid strings.
export const riskScenarioSchema = z.object({
  scenario: z.string(),
  month12: z.number(),
  month24: z.number(),
  month36: z.number(),
  assumption: z.string(),
});
export type RiskScenario = z.infer<typeof riskScenarioSchema>;

export const riskForecastSchema = z.object({
  currentRisk: z.number(),
  targetRisk: z.number(),
  reductionPct: z.number(),
  residualRisk: z.number(),
  month12: z.number(),
  month24: z.number(),
  month36: z.number(),
  // I3#7 — best/expected/worst-case bands for planning
  scenarios: z.array(riskScenarioSchema).default([]),
});
export type RiskForecast = z.infer<typeof riskForecastSchema>;

export const governanceRoleSchema = z.object({ role: z.string(), owner: z.string(), responsibility: z.string() });
export type GovernanceRole = z.infer<typeof governanceRoleSchema>;

export const remediationItemSchema = z.object({
  priority: z.number(),
  action: z.string(),
  owner: z.string(),
  affectedAssets: z.array(z.string()),
  costUsd: z.number(),
  effort: z.string(),
  riskReductionPct: z.number(),
  targetDate: z.string(),
  status: z.string(),
  dependencies: z.array(z.string()),
  validation: z.string(),
});
export type RemediationItem = z.infer<typeof remediationItemSchema>;

export const dependencyChainSchema = z.object({ path: z.string(), blastRadius: z.number(), complexity: z.string() });

/* ---- Report Intelligence sections (Reports_Enhancements_3) ---- */

// Phase 1 — Risk Scoring Transparency Engine™
// `contribution` = absolute weighted contribution (DomainRisk × Weight); the
// overall score is Σ(contribution), so an auditor can reconstruct it by hand.
export const riskWeightSchema = z.object({ domain: z.string(), weightPct: z.number(), score: z.number(), contribution: z.number(), contributionPct: z.number() });
export const riskMethodologySchema = z.object({
  formula: z.string(),
  overall: z.number(),
  weights: z.array(riskWeightSchema),
  topDriver: z.string(),
  explanation: z.string(),
});
export type RiskMethodology = z.infer<typeof riskMethodologySchema>;

// Phase 2 — AI Recommendation Validation Engine™
export const advisorValidationSchema = z.object({
  primaryExposureDomain: z.string(),
  topContributingFindings: z.array(z.string()),
  topContributingAssets: z.array(z.string()),
  expectedRiskReductionPct: z.number(),
  confidencePct: z.number(),
  why: z.string(),
});
export type AdvisorValidation = z.infer<typeof advisorValidationSchema>;

// Phase 3 — Cost Forecast Intelligence™
// I4#4 — effort is expressed the way enterprise planners consume it: raw hours
// PLUS engineer-weeks (hours ÷ 40) and FTE over the programme window.
export const costLineDetailSchema = z.object({
  category: z.string(),
  hours: z.number(),
  engineers: z.number(),
  rateUsd: z.number(),
  costUsd: z.number(),
  formula: z.string(),
  engineerWeeks: z.number().default(0),
  fte: z.number().default(0),
  effort: z.string().default(''),
});
export const costBreakdownSchema = z.object({
  blendedRateUsd: z.number(),
  totalHours: z.number(),
  totalUsd: z.number(),
  lines: z.array(costLineDetailSchema),
  windowWeeks: z.number().default(0),
  totalEngineerWeeks: z.number().default(0),
  totalFte: z.number().default(0),
  effortNote: z.string().default(''),
});
export type CostBreakdown = z.infer<typeof costBreakdownSchema>;

// Phase 5 — Asset Criticality Engine™
export const assetCriticalitySchema = z.object({
  asset: z.string(),
  businessCriticality: z.string(),
  operationalCriticality: z.string(),
  customerFacing: z.boolean(),
  internetFacing: z.boolean(),
  revenueImpact: z.string(),
  complianceScope: z.array(z.string()),
  dataSensitivity: z.string(),
});
export type AssetCriticality = z.infer<typeof assetCriticalitySchema>;

// Phase 6 — Business Impact Intelligence™ (reasons)
export const impactReasonSchema = z.object({ dimension: z.string(), level: z.string(), reason: z.string(), evidence: z.array(z.string()).default([]) });
export type ImpactReason = z.infer<typeof impactReasonSchema>;

// Phase 7 — Finding Deduplication Engine™
export const findingGroupSchema = z.object({ title: z.string(), occurrences: z.number(), affectedAssets: z.number(), evidence: z.array(z.string()), impact: z.enum(SEVERITIES) });
export type FindingGroup = z.infer<typeof findingGroupSchema>;

// Phase 8 — Migration Confidence Scoring™
export const confidenceFactorSchema = z.object({ label: z.string(), coveragePct: z.number() });
export const migrationConfidenceSchema = z.object({ overallPct: z.number(), factors: z.array(confidenceFactorSchema) });
export type MigrationConfidence = z.infer<typeof migrationConfidenceSchema>;

// Phase 9 — Evidence Confidence Scoring™
export const evidenceConfidenceSchema = z.object({ source: z.string(), coveragePct: z.number(), completenessPct: z.number(), freshness: z.string(), confidencePct: z.number(), note: z.string() });
export type EvidenceConfidence = z.infer<typeof evidenceConfidenceSchema>;

// Shared Responsibility Quantum Migration Intelligence™ — ownership assessment
export const sharedResponsibilityReportSchema = z.object({
  hasData: z.boolean().default(false),
  summary: z.string().default(EVIDENCE_UNAVAILABLE),
  readiness: z.object({ overall: z.number(), customer: z.number(), provider: z.number(), ecosystem: z.number() }).default({ overall: 0, customer: 0, provider: 0, ecosystem: 0 }),
  distribution: z.object({ customer: z.number(), provider: z.number(), ecosystem: z.number() }).default({ customer: 0, provider: 0, ecosystem: 0 }),
  customerControlled: z.number().default(0),
  providerControlled: z.number().default(0),
  ecosystemDependent: z.number().default(0),
  actionableNow: z.number().default(0),
  waitingDependencies: z.number().default(0),
  migrationBlockers: z.number().default(0),
  // CONSOLIDATED ownership rows — one cryptographic exposure, per owner, per
  // asset. `occurrences` carries the raw scanner instances behind the row, so
  // the consolidation is auditable and no export prints repeated rows.
  matrix: z
    .array(
      z.object({
        finding: z.string(),
        asset: z.string().default(EVIDENCE_UNAVAILABLE),
        owner: z.string(),
        action: z.string(),
        priority: z.string(),
        status: z.string(),
        domain: z.string(),
        occurrences: z.number().default(1),
        detectionLabels: z.array(z.string()).default([]),
      }),
    )
    .default([]),
  /** Raw scanner instances represented by `matrix` (Σ occurrences). */
  matrixInstances: z.number().default(0),
  blockers: z.array(z.object({ title: z.string(), owner: z.string(), dependency: z.string() })).default([]),
  waves: z.array(z.object({ wave: z.number(), name: z.string(), domain: z.string(), findingCount: z.number(), status: z.string(), timeline: z.string() })).default([]),
  providers: z.array(z.object({ name: z.string(), domain: z.string(), count: z.number(), pqRoadmap: z.string(), customerInfluence: z.string() })).default([]),
  // Reports_Generation_Improvements_06 §4 — per-domain readiness timeline
  // ("Customer Ready · Provider Waiting · Ecosystem Waiting") for an at-a-glance
  // executive view of where progress can actually be made today.
  timeline: z.array(z.object({ domain: z.string(), label: z.string(), status: z.string(), readiness: z.number(), note: z.string() })).default([]),
  // Improvements_06 minor §1 — finding-count reconciliation (classified vs raw).
  classifiedFindings: z.number().default(0),
  rawScannerInstances: z.number().default(0),
  reconciliationNote: z.string().default(''),
  nextActions: z.array(z.string()).default([]),
  note: z.string().default(''),
});
export type SharedResponsibilityReport = z.infer<typeof sharedResponsibilityReportSchema>;

/* ---- Reports_Generation_Improvements_06 — board-level visual intelligence ---- */

// §6 — Executive One-Page Board Snapshot. Every value is copied from an
// already-validated section (executive block, ROI, decisions, shared
// responsibility, certification) so the 60-second summary can never disagree
// with the report body.
export const boardSnapshotMetricSchema = z.object({ label: z.string(), value: z.string(), context: z.string().default('') });
export type BoardSnapshotMetric = z.infer<typeof boardSnapshotMetricSchema>;
export const boardSnapshotSchema = z.object({
  hasData: z.boolean().default(false),
  headline: z.string().default(EVIDENCE_UNAVAILABLE),
  certificationStatus: z.string().default(''),
  certified: z.boolean().default(false),
  currentReadiness: z.number().default(0),
  targetReadiness: z.number().default(0),
  currentRisk: z.number().default(0),
  targetRisk: z.number().default(0),
  investmentUsd: z.number().default(0),
  timelineWeeks: z.number().default(0),
  roiSummary: z.string().default(EVIDENCE_UNAVAILABLE),
  riskReductionPct: z.number().default(0),
  metrics: z.array(boardSnapshotMetricSchema).default([]),
  topDecisions: z.array(z.string()).default([]),
  responsibilitySplit: z.object({ customer: z.number(), provider: z.number(), ecosystem: z.number() }).default({ customer: 0, provider: 0, ecosystem: 0 }),
  responsibilityNote: z.string().default(''),
  assetBasis: z.string().default(''),
  recommendation: z.string().default(''),
});
export type BoardSnapshot = z.infer<typeof boardSnapshotSchema>;

// §2 — 5×5 Executive Heat Map (Business Impact × Quantum Exploitation Likelihood).
export const heatMapCellSchema = z.object({
  impact: z.string(),
  likelihood: z.string(),
  impactRank: z.number(),
  likelihoodRank: z.number(),
  count: z.number(),
  level: z.string(),
  items: z.array(z.string()).default([]),
});
export type HeatMapCell = z.infer<typeof heatMapCellSchema>;
export const executiveHeatMapSchema = z.object({
  hasData: z.boolean().default(false),
  impactLabels: z.array(z.string()).default([]),
  likelihoodLabels: z.array(z.string()).default([]),
  cells: z.array(heatMapCellSchema).default([]),
  totalPlotted: z.number().default(0),
  methodology: z.string().default(''),
  note: z.string().default(''),
});
export type ExecutiveHeatMap = z.infer<typeof executiveHeatMapSchema>;

// §3 — Business Priority Matrix (Business Value × Effort → Quick Wins /
// Strategic Projects / Fill-Ins / Long-Term) to guide CIO investment.
export const priorityMatrixItemSchema = z.object({
  name: z.string(),
  riskReductionPct: z.number(),
  effort: z.string(),
  businessValue: z.string(),
  rationale: z.string(),
});
export type PriorityMatrixItem = z.infer<typeof priorityMatrixItemSchema>;
export const priorityQuadrantSchema = z.object({
  key: z.string(),
  title: z.string(),
  subtitle: z.string(),
  guidance: z.string(),
  items: z.array(priorityMatrixItemSchema).default([]),
});
export type PriorityQuadrant = z.infer<typeof priorityQuadrantSchema>;
export const businessPriorityMatrixSchema = z.object({
  hasData: z.boolean().default(false),
  quadrants: z.array(priorityQuadrantSchema).default([]),
  note: z.string().default(''),
});
export type BusinessPriorityMatrix = z.infer<typeof businessPriorityMatrixSchema>;

// §5 — Evidence Quality Score (letter grade per evidence source; "Missing" when
// a source has produced no telemetry) — easier to digest than a raw %.
export const evidenceQualityRowSchema = z.object({
  source: z.string(),
  grade: z.string(),
  confidencePct: z.number(),
  status: z.string(),
  note: z.string().default(''),
});
export type EvidenceQualityRow = z.infer<typeof evidenceQualityRowSchema>;
export const evidenceQualitySchema = z.object({
  rows: z.array(evidenceQualityRowSchema).default([]),
  overallGrade: z.string().default('-'),
  gradedSources: z.number().default(0),
  missingSources: z.number().default(0),
  note: z.string().default(''),
});
export type EvidenceQuality = z.infer<typeof evidenceQualitySchema>;

// Minor §3 — Remediation Campaigns: consolidate repeated recommendations under a
// single campaign theme so the report is shorter and executive-friendly without
// losing traceability.
export const remediationCampaignSchema = z.object({
  campaign: z.string(),
  target: z.string(),
  action: z.string(),
  findings: z.array(z.string()).default([]),
  findingCount: z.number().default(0),
  affectedAssets: z.number().default(0),
  occurrences: z.number().default(0),
  riskReductionPct: z.number().default(0),
  priority: z.string().default(''),
});
export type RemediationCampaign = z.infer<typeof remediationCampaignSchema>;
export const remediationCampaignsSchema = z.object({
  campaigns: z.array(remediationCampaignSchema).default([]),
  note: z.string().default(''),
});
export type RemediationCampaigns = z.infer<typeof remediationCampaignsSchema>;

// Phase 10 — Executive Decision Center™
export const executiveDecisionSchema = z.object({ decision: z.string(), type: z.string(), rationale: z.string(), owner: z.string() });
export type ExecutiveDecision = z.infer<typeof executiveDecisionSchema>;

// Phase 11 — Enterprise Remediation Playbook™
// I4#6 — operational execution fields (downtime / window / rollback duration /
// validation owner / success KPI / automation / SLA impact) so each playbook
// reads as a change-management-ready runbook.
export const playbookDetailSchema = z.object({
  finding: z.string(),
  currentState: z.string(),
  targetState: z.string(),
  prerequisites: z.array(z.string()),
  dependencies: z.array(z.string()),
  executionSteps: z.array(z.string()),
  validationSteps: z.array(z.string()),
  rollbackSteps: z.array(z.string()),
  successCriteria: z.array(z.string()),
  estimatedDowntime: z.string().default(EVIDENCE_UNAVAILABLE),
  maintenanceWindow: z.string().default(EVIDENCE_UNAVAILABLE),
  rollbackDuration: z.string().default(EVIDENCE_UNAVAILABLE),
  validationOwner: z.string().default(EVIDENCE_UNAVAILABLE),
  successKpi: z.string().default(EVIDENCE_UNAVAILABLE),
  automationStatus: z.string().default(EVIDENCE_UNAVAILABLE),
  slaImpact: z.string().default(EVIDENCE_UNAVAILABLE),
});
export type PlaybookDetail = z.infer<typeof playbookDetailSchema>;

// Change-management controls that are identical for EVERY playbook, hoisted out
// of the per-playbook tables and stated once. `sharedKeys` tells the exporters
// which per-playbook rows to omit so nothing is printed twice.
export const playbookStandardControlsSchema = z.object({
  /** Number of playbooks these controls govern. */
  applies: z.number().default(0),
  /** Row keys hoisted out of the per-playbook tables. */
  sharedKeys: z.array(z.string()).default([]),
  rows: z.array(z.object({ step: z.string(), detail: z.string() })).default([]),
  note: z.string().default(''),
});
export type PlaybookStandardControls = z.infer<typeof playbookStandardControlsSchema>;

// I4#5 follow-up — when every risk disposition carries the same approval status,
// date and signature method, they are stated once as policy instead of repeated
// on every row. `uniform: false` keeps the full per-row columns.
export const riskApprovalPolicySchema = z.object({
  uniform: z.boolean().default(false),
  status: z.string().default(''),
  approvalDate: z.string().default(''),
  method: z.string().default(''),
  note: z.string().default(''),
});
export type RiskApprovalPolicy = z.infer<typeof riskApprovalPolicySchema>;

// Phase 12 — Migration Simulation Engine™
export const waveSimulationSchema = z.object({ label: z.string(), readinessFrom: z.number(), readinessTo: z.number(), riskFrom: z.number(), riskTo: z.number(), costUsd: z.number(), timelineWeeks: z.number(), confidencePct: z.number() });
export type WaveSimulation = z.infer<typeof waveSimulationSchema>;

// Phase 13 — Enterprise Governance gates
export const governanceGateSchema = z.object({ gate: z.string(), owner: z.string(), criteria: z.string() });
export type GovernanceGate = z.infer<typeof governanceGateSchema>;

// Phase 14 — Report Explainability Requirements™
export const explainabilitySchema = z.object({ metric: z.string(), what: z.string(), how: z.string(), evidence: z.string(), why: z.string(), action: z.string() });
export type Explainability = z.infer<typeof explainabilitySchema>;

export const kpiSchema = z.object({
  label: z.string(),
  value: z.union([z.string(), z.number()]),
  unit: z.string().optional(),
  level: z.string().optional(),
  tone: z.enum(['critical', 'high', 'medium', 'low', 'good', 'neutral']).default('neutral'),
});
export type ReportKpi = z.infer<typeof kpiSchema>;

export const tableSchema = z.object({
  title: z.string(),
  columns: z.array(z.string()),
  rows: z.array(z.array(z.union([z.string(), z.number()]))),
});
export type ReportTable = z.infer<typeof tableSchema>;

export const complianceMappingSchema = z.object({
  framework: z.string(),
  control: z.string(),
  status: z.enum(['aligned', 'partial', 'gap', 'not-assessed']),
  detail: z.string(),
  // I2#7 — dynamic gap tracking: Current / Target / Gap / Progress per framework
  currentPct: z.number().default(0),
  targetPct: z.number().default(0),
  gapPct: z.number().default(0),
  progressPct: z.number().default(0),
});
export type ComplianceMapping = z.infer<typeof complianceMappingSchema>;

export const roadmapPhaseSchema = z.object({
  phase: z.string(),
  description: z.string(),
  status: z.string(),
  effortWeeks: z.number(),
  // Program-management enrichment (#8)
  startDate: z.string().default(EVIDENCE_UNAVAILABLE),
  endDate: z.string().default(EVIDENCE_UNAVAILABLE),
  milestone: z.string().default(''),
  gate: z.string().default(''),
  criticalPath: z.boolean().default(false),
  slackWeeks: z.number().default(0),
});
export type RoadmapPhase = z.infer<typeof roadmapPhaseSchema>;

// #9 — Executive Risk Acceptance register
// I4#5 — formal Risk Owner Approval fields (approver / status / date / method).
// Approvals are never fabricated: entries are generated as "Pending Executive
// Sign-off" and the approval is executed against the report's digital
// signature (SHA3-256 integrity hash + verification token).
export const riskAcceptanceSchema = z.object({
  risk: z.string(),
  decision: z.enum(['Mitigate', 'Accept', 'Transfer', 'Defer']),
  owner: z.string(),
  rationale: z.string(),
  residualRisk: z.string(),
  reviewDate: z.string().default(EVIDENCE_UNAVAILABLE),
  approver: z.string().default('CISO'),
  approvalStatus: z.string().default('Pending Executive Sign-off'),
  approvalDate: z.string().default('Pending sign-off'),
  approvalMethod: z.string().default('Digital signature — report SHA3-256 integrity hash + verification token'),
});
export type RiskAcceptance = z.infer<typeof riskAcceptanceSchema>;

// #10 — Asset-Level Readiness
// I4#3/#7 — enriched into an executive asset inventory: business context
// (unit / environment / criticality / platform / cloud) plus per-asset crypto
// posture (TLS version, cert expiry, primary algorithm, key size, PQC status,
// HNDL exposure). Fields the evidence pipeline has not observed are
// `Evidence Not Available`, never invented.
export const assetReadinessSchema = z.object({
  asset: z.string(),
  readiness: z.number(),
  risk: z.number(),
  posture: z.string(),
  internetFacing: z.boolean(),
  primaryDriver: z.string(),
  owner: z.string(),
  businessUnit: z.string().default(EVIDENCE_UNAVAILABLE),
  environment: z.string().default(EVIDENCE_UNAVAILABLE),
  criticality: z.string().default(EVIDENCE_UNAVAILABLE),
  platform: z.string().default(EVIDENCE_UNAVAILABLE),
  cloudProvider: z.string().default(EVIDENCE_UNAVAILABLE),
  tlsVersion: z.string().default(EVIDENCE_UNAVAILABLE),
  certExpiry: z.string().default(EVIDENCE_UNAVAILABLE),
  primaryAlgorithm: z.string().default(EVIDENCE_UNAVAILABLE),
  keySize: z.string().default(EVIDENCE_UNAVAILABLE),
  pqcStatus: z.string().default(EVIDENCE_UNAVAILABLE),
  hndlExposure: z.string().default(EVIDENCE_UNAVAILABLE),
});
export type AssetReadiness = z.infer<typeof assetReadinessSchema>;

// Architectural — Decision Traceability (Evidence → … → Approval)
export const decisionChainStepSchema = z.object({ stage: z.string(), detail: z.string() });
export const decisionChainSchema = z.object({ headline: z.string(), steps: z.array(decisionChainStepSchema) });
export type DecisionChain = z.infer<typeof decisionChainSchema>;

/* ---- Improvements_02 — enterprise-grade report intelligence ---- */

// I2#1/#3 — Readiness Scoring Methodology™: the exact readiness formula with a
// per-factor Weight × Score = Contribution table. Unmeasured factors (e.g.
// runtime visibility with zero runtime telemetry) are marked `measured: false`,
// excluded from the blend and the remaining weights renormalised — the score is
// fully auditable and never contradicts the evidence dashboard.
export const readinessFactorContributionSchema = z.object({
  factor: z.string(),
  weightPct: z.number(),
  score: z.union([z.number(), z.string()]), // number, or 'Not Measured'
  contribution: z.number(),
  measured: z.boolean().default(true),
  basis: z.string().default(''),
});
export const readinessMethodologySchema = z.object({
  formula: z.string(),
  overall: z.number(),
  factors: z.array(readinessFactorContributionSchema),
  explanation: z.string(),
});
export type ReadinessMethodology = z.infer<typeof readinessMethodologySchema>;

// I2#4 — Executive ROI & Value Intelligence™
// I3#2 — assumptions are exposed and configurable (ALE/SLE/FAIR-oriented) rather
// than a hidden constant, so ROI can be made organization-specific in production.
export const roiLineSchema = z.object({ metric: z.string(), value: z.string(), basis: z.string() });
export const roiAnalysisSchema = z.object({
  investmentUsd: z.number(),
  expectedRiskReductionPct: z.number(),
  riskAvoidanceUsd: z.number(),
  netBenefitUsd: z.number(),
  roiMultiple: z.number(),
  paybackNarrative: z.string(),
  lines: z.array(roiLineSchema),
  // I3#2 — exposed ROI assumptions (configurable per organization)
  riskAvoidanceMultiple: z.number().default(3),
  annualLossExpectancyUsd: z.number().default(0),
  assumptionBasis: z.string().default(EVIDENCE_UNAVAILABLE),
  assumptionsConfigurable: z.boolean().default(true),
});
export type RoiAnalysis = z.infer<typeof roiAnalysisSchema>;

// I2#5 / I3#5 — Migration Resource Loading™ (per-team allocation + capacity + deps)
export const resourceLoadSchema = z.object({
  team: z.string(),
  waves: z.string(),
  hours: z.number(),
  engineers: z.number(),
  windowWeeks: z.number(),
  allocationPct: z.number(),
  // I3#5 — planning inputs
  availabilityPct: z.number().default(100),
  dependencies: z.array(z.string()).default([]),
  basis: z.string().default(''),
});
export type ResourceLoad = z.infer<typeof resourceLoadSchema>;

// I3#1 — Confidence taxonomy: distinct confidence concepts, clearly labelled
// so "72% assessment confidence" is never confused with per-wave confidence.
// I4#1 — adds Migration Forecast Confidence (the entire-programme simulation
// confidence) as its own labelled measure, removing the last ambiguity between
// assessment-evidence confidence and forecast confidence.
export const confidenceSummarySchema = z.object({
  assessmentConfidencePct: z.number(),
  migrationPlanConfidencePct: z.number(),
  migrationForecastConfidencePct: z.number().default(0),
  waveConfidenceRange: z.string(),
  evidenceConfidencePct: z.number(),
  note: z.string(),
});
export type ConfidenceSummary = z.infer<typeof confidenceSummarySchema>;

// I4#2 — Readiness Progression Ladder™: executive wording for the migration
// simulation ("Current Readiness → Projected After Wave 1 → … → Target
// Readiness") instead of bare "19 → 47" arrows.
export const readinessProgressionStepSchema = z.object({
  stage: z.string(),
  readiness: z.number(),
  risk: z.number(),
  detail: z.string().default(''),
});
export type ReadinessProgressionStep = z.infer<typeof readinessProgressionStepSchema>;

// I4#9 — Executive Certification Summary™: the report's final page. Every
// value is copied from already-validated report sections; certification status
// is COMPUTED from published criteria, never asserted.
// I5#4 — carries the dated migration milestone schedule (from the programme
// roadmap) so the certification page reads as an actionable executive roadmap.
export const certificationCriterionSchema = z.object({
  criterion: z.string(),
  required: z.string(),
  actual: z.string(),
  met: z.boolean(),
});
export type CertificationCriterion = z.infer<typeof certificationCriterionSchema>;
export const certificationMilestoneSchema = z.object({
  milestone: z.string(),
  window: z.string(),
  gate: z.string().default(''),
});
export type CertificationMilestone = z.infer<typeof certificationMilestoneSchema>;
export const certificationSummarySchema = z.object({
  overallReadiness: z.number(),
  readinessLevel: z.string(),
  assessmentConfidencePct: z.number(),
  migrationForecastConfidencePct: z.number(),
  residualRisk: z.number(),
  residualRiskLevel: z.string(),
  migrationStatus: z.string(),
  scopeStatement: z.string(),
  certificationStatus: z.string(),
  certified: z.boolean(),
  criteria: z.array(certificationCriterionSchema),
  milestones: z.array(certificationMilestoneSchema).default([]),
  attestation: z.string(),
  signedBy: z.string(),
  signedRole: z.string(),
  verificationHint: z.string().default(''),
});
export type CertificationSummary = z.infer<typeof certificationSummarySchema>;

// I5#5 — Executive Decision Package™: the one-look decision summary leadership
// needs alongside the decision register (budget, resources, accepted/deferred
// risks, timeline, ROI, business impact) — every line sourced from validated
// report sections.
export const decisionPackageLineSchema = z.object({ item: z.string(), value: z.string(), detail: z.string() });
export type DecisionPackageLine = z.infer<typeof decisionPackageLineSchema>;

export const DEFAULT_CERTIFICATION: CertificationSummary = {
  overallReadiness: 0,
  readinessLevel: '',
  assessmentConfidencePct: 0,
  migrationForecastConfidencePct: 0,
  residualRisk: 0,
  residualRiskLevel: '',
  migrationStatus: EVIDENCE_UNAVAILABLE,
  scopeStatement: '',
  certificationStatus: 'Not Certified — No Assessment Evidence',
  certified: false,
  criteria: [],
  milestones: [],
  attestation: '',
  signedBy: '',
  signedRole: '',
  verificationHint: '',
};

// I3#8 — Operational (non-financial) business value beyond ROI
export const operationalBenefitSchema = z.object({ benefit: z.string(), impact: z.string(), evidence: z.string() });
export type OperationalBenefit = z.infer<typeof operationalBenefitSchema>;

// I3#9 — Executive Maturity Model (CMMI-style Level 0-5 per crypto domain)
export const maturityDomainSchema = z.object({
  domain: z.string(),
  currentLevel: z.number(),
  currentLabel: z.string(),
  targetLevel: z.number(),
  targetLabel: z.string(),
  gap: z.number(),
  timeline: z.string(),
  investment: z.string(),
  owner: z.string(),
  dependencies: z.string(),
});
export const maturityModelSchema = z.object({ scale: z.string(), domains: z.array(maturityDomainSchema), note: z.string() });
export type MaturityModel = z.infer<typeof maturityModelSchema>;

// I2#6 / I3#3 / I3#4 — Asset Intelligence Profile™ (deep per-asset crypto posture,
// richer owner/business metadata, and platform/hosting fields). Fields the
// evidence pipeline does not observe are `Evidence Not Available`, never invented.
export const assetIntelligenceSchema = z.object({
  asset: z.string(),
  assetType: z.string().default(EVIDENCE_UNAVAILABLE),
  environment: z.string().default(EVIDENCE_UNAVAILABLE),
  ownerDepartment: z.string().default(EVIDENCE_UNAVAILABLE),
  // I3#3 — richer ownership + business context
  businessOwner: z.string().default('Unknown'),
  businessUnit: z.string().default(EVIDENCE_UNAVAILABLE),
  businessCriticality: z.string().default(EVIDENCE_UNAVAILABLE),
  // I3#4 — platform / hosting metadata
  os: z.string().default(EVIDENCE_UNAVAILABLE),
  platform: z.string().default(EVIDENCE_UNAVAILABLE),
  hosting: z.string().default(EVIDENCE_UNAVAILABLE),
  cloudProvider: z.string().default(EVIDENCE_UNAVAILABLE),
  certificates: z.string().default(EVIDENCE_UNAVAILABLE),
  certExpiry: z.string().default(EVIDENCE_UNAVAILABLE),
  tlsVersion: z.string().default(EVIDENCE_UNAVAILABLE),
  primaryAlgorithm: z.string().default(EVIDENCE_UNAVAILABLE),
  keyLength: z.string().default(EVIDENCE_UNAVAILABLE),
  algorithms: z.array(z.string()).default([]),
  keySizes: z.array(z.string()).default([]),
  cryptoLibraries: z.string().default(EVIDENCE_UNAVAILABLE),
  dependencies: z.array(z.string()).default([]),
  pqcReadinessPct: z.number().default(0),
  migrationComplexity: z.string().default('Medium'),
  estimatedHours: z.number().default(0),
});
export type AssetIntelligence = z.infer<typeof assetIntelligenceSchema>;

// I2#9 — Industry Benchmarking™ (peer values are modeled reference points)
export const benchmarkRowSchema = z.object({ cohort: z.string(), readiness: z.number(), delta: z.number(), source: z.string() });
export const benchmarkingSchema = z.object({ rows: z.array(benchmarkRowSchema), percentileNarrative: z.string(), note: z.string() });
export type Benchmarking = z.infer<typeof benchmarkingSchema>;

// I2#10 — Report Validation™ (self-verified arithmetic/consistency badge)
export const validationCheckSchema = z.object({ check: z.string(), status: z.enum(['pass', 'fail']), detail: z.string() });
export const reportValidationSchema = z.object({ overall: z.enum(['PASS', 'FAIL']), checks: z.array(validationCheckSchema), note: z.string().default('') });
export type ReportValidation = z.infer<typeof reportValidationSchema>;

// I2#11 — Quantum Readiness Index™ (strategic pillars behind the single score)
export const readinessPillarSchema = z.object({
  pillar: z.string(),
  score: z.union([z.number(), z.string()]), // number, or 'Not Measured'
  weightPct: z.number(),
  contribution: z.number(),
  measured: z.boolean().default(true),
  driver: z.string().default(''),
});
export const readinessIndexSchema = z.object({ overall: z.number(), pillars: z.array(readinessPillarSchema), note: z.string() });
export type ReadinessIndex = z.infer<typeof readinessIndexSchema>;

// I2#12 — Policy-driven PQC algorithm profiles (no hard-coded universal target)
export const cryptoPolicyProfileSchema = z.object({
  profile: z.string(),
  keyEstablishment: z.string(),
  digitalSignature: z.string(),
  certificateChain: z.string(),
  symmetric: z.string(),
  hash: z.string(),
  guidance: z.string(),
});
export const cryptoPolicySchema = z.object({ activeProfile: z.string(), profiles: z.array(cryptoPolicyProfileSchema), note: z.string() });
export type CryptoPolicy = z.infer<typeof cryptoPolicySchema>;

// I2#2 — Terminology & Definitions (Assets vs Components etc.)
export const definitionSchema = z.object({ term: z.string(), definition: z.string() });
export type ReportDefinition = z.infer<typeof definitionSchema>;

export const brandingSchema = z.object({
  companyName: z.string().default('QGuard Helix'),
  companyLogo: z.string().nullable().default(null), // data URL or storage URL
  businessUnit: z.string().default(''),
  reportOwner: z.string().default(''),
  reviewer: z.string().default(''),
  classification: z.string().default('CONFIDENTIAL'),
  reportVersion: z.string().default('1.0'),
  customNotes: z.string().default(''),
});
export type ReportBranding = z.infer<typeof brandingSchema>;

export const chartImageSchema = z.object({
  key: z.string(),
  title: z.string(),
  dataUrl: z.string(), // PNG data URL for embedding
});
export type ReportChartImage = z.infer<typeof chartImageSchema>;

// Asset-scoped reporting — records exactly which discovered assets the report
// covers. `full` = whole assessment; `custom` = user-selected subset, with the
// selected assets listed and the attribution methodology disclosed.
export const reportScopeAssetSchema = z.object({
  name: z.string(),
  key: z.string().default(''),
  assetType: z.string().default('asset'),
  environment: z.string().default('unknown'),
  riskScore: z.number().default(0),
  posture: z.string().default('unknown'),
});
export type ReportScopeAsset = z.infer<typeof reportScopeAssetSchema>;

export const reportScopeSchema = z.object({
  type: z.enum(['full', 'custom']).default('full'),
  selectedAssetCount: z.number().default(0),
  totalAssetCount: z.number().default(0),
  assets: z.array(reportScopeAssetSchema).default([]),
  note: z.string().default(''),
  methodology: z.string().default(''),
});
export type ReportScope = z.infer<typeof reportScopeSchema>;

export const DEFAULT_REPORT_SCOPE: ReportScope = {
  type: 'full',
  selectedAssetCount: 0,
  totalAssetCount: 0,
  assets: [],
  note: '',
  methodology: '',
};

export const reportMetaSchema = z.object({
  id: z.string(),
  kind: z.enum(REPORT_KINDS),
  title: z.string(),
  generatedAt: z.string(),
  generatedBy: z.string(),
  version: z.string(),
  tenantScoped: z.boolean().default(true),
  sourceGeneratedAt: z.string().nullable(),
});
export type ReportMeta = z.infer<typeof reportMetaSchema>;

export const integritySchema = z.object({
  algorithm: z.string(), // SHA3-256
  hash: z.string(),
  signedAt: z.string(),
  verificationToken: z.string().optional(),
});
export type ReportIntegrity = z.infer<typeof integritySchema>;

export const reportSourceCoverageSchema = z.object({
  source: z.string(),
  status: z.enum(['available', 'missing', 'partial']),
  detail: z.string(),
});
export const reportProvenanceSchema = z.object({
  reportId: z.string().uuid(),
  workspaceOwnerId: z.string().uuid(),
  organizationId: z.string().uuid().nullable(),
  snapshotAt: z.string().datetime(),
  assetInventoryVersion: z.string().nullable(),
  cbomVersion: z.string().nullable(),
  assessmentId: z.string().nullable(),
  validationStatus: z.enum(['validated', 'incomplete']),
  dataCompleteness: z.array(reportSourceCoverageSchema),
});
export type ReportProvenance = z.infer<typeof reportProvenanceSchema>;

// A captured assessment carries only observed facts and explicitly attributed
// assessment outputs. Legacy planning reports have a separate schema.
export const evidenceAssessmentReportSchema = z.object({
  meta: reportMetaSchema,
  scope: reportScopeSchema.extend({
    assets: z.array(reportScopeAssetSchema.extend({ riskScore: z.number().nullable() })),
  }),
  branding: brandingSchema,
  executiveSummary: z.string(),
  kpis: z.array(kpiSchema),
  findings: z.array(findingSchema.pick({
    id: true, title: true, severity: true, evidence: true, affectedAssets: true,
    recommendation: true, source: true, detectedAt: true,
  })),
  tables: z.array(tableSchema),
  provenance: reportProvenanceSchema,
  integrity: integritySchema.optional(),
});
export type EvidenceAssessmentReport = z.infer<typeof evidenceAssessmentReportSchema>;

export const enterpriseAssessmentReportSchema = z.object({
  meta: reportMetaSchema,
  // Default keeps previously-saved report JSON parseable (pre-scope reports = full scope).
  scope: reportScopeSchema.default(DEFAULT_REPORT_SCOPE),
  branding: brandingSchema,
  executiveSummary: z.string(),
  executiveBlock: executiveBlockSchema,
  kpis: z.array(kpiSchema),
  businessImpact: businessImpactSchema,
  readinessDomains: z.array(readinessDomainSchema),
  migrationAdvisor: migrationAdvisorSchema,
  migrationReadiness: z.array(z.object({ category: z.string(), score: z.number(), recommendation: z.string() })),
  migrationWaves: z.array(migrationWaveSchema),
  dependencyAnalysis: z.object({ chains: z.array(dependencyChainSchema), failurePoints: z.array(z.string()), summary: z.string() }),
  riskCategories: z.array(riskCategorySchema),
  // Report Intelligence (Reports_Enhancements_3)
  riskMethodology: riskMethodologySchema,
  advisorValidation: advisorValidationSchema,
  costBreakdown: costBreakdownSchema,
  assetCriticality: z.array(assetCriticalitySchema),
  impactReasons: z.array(impactReasonSchema),
  findingGroups: z.array(findingGroupSchema),
  migrationConfidence: migrationConfidenceSchema,
  evidenceConfidence: z.array(evidenceConfidenceSchema),
  executiveDecisions: z.array(executiveDecisionSchema),
  // Shared Responsibility Assessment™ (default keeps older report JSON parseable)
  sharedResponsibility: sharedResponsibilityReportSchema.default({
    hasData: false,
    summary: EVIDENCE_UNAVAILABLE,
    readiness: { overall: 0, customer: 0, provider: 0, ecosystem: 0 },
    distribution: { customer: 0, provider: 0, ecosystem: 0 },
    customerControlled: 0,
    providerControlled: 0,
    ecosystemDependent: 0,
    actionableNow: 0,
    waitingDependencies: 0,
    migrationBlockers: 0,
    matrix: [],
    matrixInstances: 0,
    blockers: [],
    waves: [],
    providers: [],
    timeline: [],
    classifiedFindings: 0,
    rawScannerInstances: 0,
    reconciliationNote: '',
    nextActions: [],
    note: '',
  }),
  playbookDetail: z.array(playbookDetailSchema),
  playbookStandardControls: playbookStandardControlsSchema.default({ applies: 0, sharedKeys: [], rows: [], note: '' }),
  riskApprovalPolicy: riskApprovalPolicySchema.default({ uniform: false, status: '', approvalDate: '', method: '', note: '' }),
  waveSimulation: z.array(waveSimulationSchema),
  governanceGates: z.array(governanceGateSchema),
  explainability: z.array(explainabilitySchema),
  // Improvements_01
  riskAcceptance: z.array(riskAcceptanceSchema),
  assetReadiness: z.array(assetReadinessSchema),
  decisionChain: decisionChainSchema,
  // Improvements_02 — defaults keep previously-saved report JSON parseable
  readinessMethodology: readinessMethodologySchema.default({ formula: '', overall: 0, factors: [], explanation: EVIDENCE_UNAVAILABLE }),
  readinessIndex: readinessIndexSchema.default({ overall: 0, pillars: [], note: EVIDENCE_UNAVAILABLE }),
  roiAnalysis: roiAnalysisSchema.default({ investmentUsd: 0, expectedRiskReductionPct: 0, riskAvoidanceUsd: 0, netBenefitUsd: 0, roiMultiple: 0, paybackNarrative: EVIDENCE_UNAVAILABLE, lines: [], riskAvoidanceMultiple: 3, annualLossExpectancyUsd: 0, assumptionBasis: EVIDENCE_UNAVAILABLE, assumptionsConfigurable: true }),
  resourceLoading: z.array(resourceLoadSchema).default([]),
  assetIntelligence: z.array(assetIntelligenceSchema).default([]),
  benchmarking: benchmarkingSchema.default({ rows: [], percentileNarrative: EVIDENCE_UNAVAILABLE, note: '' }),
  reportValidation: reportValidationSchema.default({ overall: 'FAIL', checks: [], note: 'Validation not executed for this report version.' }),
  cryptoPolicy: cryptoPolicySchema.default({ activeProfile: '', profiles: [], note: '' }),
  definitions: z.array(definitionSchema).default([]),
  // Improvements_03 — refinements (defaults keep older report JSON parseable)
  confidenceSummary: confidenceSummarySchema.default({ assessmentConfidencePct: 0, migrationPlanConfidencePct: 0, migrationForecastConfidencePct: 0, waveConfidenceRange: EVIDENCE_UNAVAILABLE, evidenceConfidencePct: 0, note: '' }),
  operationalBenefits: z.array(operationalBenefitSchema).default([]),
  maturityModel: maturityModelSchema.default({ scale: '', domains: [], note: EVIDENCE_UNAVAILABLE }),
  // Improvements_04 — refinements (defaults keep older report JSON parseable)
  readinessProgression: z.array(readinessProgressionStepSchema).default([]),
  certification: certificationSummarySchema.default(DEFAULT_CERTIFICATION),
  // Improvements_05 — refinements (defaults keep older report JSON parseable)
  decisionPackage: z.array(decisionPackageLineSchema).default([]),
  // Improvements_06 — board-level visual intelligence (defaults keep older JSON parseable)
  boardSnapshot: boardSnapshotSchema.default({
    hasData: false,
    headline: EVIDENCE_UNAVAILABLE,
    certificationStatus: '',
    certified: false,
    currentReadiness: 0,
    targetReadiness: 0,
    currentRisk: 0,
    targetRisk: 0,
    investmentUsd: 0,
    timelineWeeks: 0,
    roiSummary: EVIDENCE_UNAVAILABLE,
    riskReductionPct: 0,
    metrics: [],
    topDecisions: [],
    responsibilitySplit: { customer: 0, provider: 0, ecosystem: 0 },
    responsibilityNote: '',
    assetBasis: '',
    recommendation: '',
  }),
  executiveHeatMap: executiveHeatMapSchema.default({ hasData: false, impactLabels: [], likelihoodLabels: [], cells: [], totalPlotted: 0, methodology: '', note: '' }),
  businessPriorityMatrix: businessPriorityMatrixSchema.default({ hasData: false, quadrants: [], note: '' }),
  evidenceQuality: evidenceQualitySchema.default({ rows: [], overallGrade: '-', gradedSources: 0, missingSources: 0, note: '' }),
  remediationCampaigns: remediationCampaignsSchema.default({ campaigns: [], note: '' }),
  findings: z.array(findingSchema),
  assets: tableSchema,
  certificates: tableSchema,
  keys: tableSchema,
  tlsEndpoints: tableSchema,
  cbom: tableSchema,
  hndl: z.object({ summary: z.string(), table: tableSchema, categories: z.array(hndlCategorySchema) }),
  trustRelationships: tableSchema,
  pqcReadiness: z.object({ summary: z.string(), table: tableSchema }),
  compliance: z.array(complianceMappingSchema),
  remediationProgram: z.array(remediationItemSchema),
  roadmap: z.array(roadmapPhaseSchema),
  playbook: z.array(playbookStageSchema),
  costForecast: costForecastSchema,
  riskForecast: riskForecastSchema,
  governance: z.array(governanceRoleSchema),
  remediation: tableSchema,
  // I5#2 — sources that produced evidence vs telemetry that is not yet available
  // are listed separately, so unavailable sources are never implied to have
  // contributed evidence.
  evidence: z.object({ sources: z.array(z.string()), unavailableSources: z.array(z.string()).default([]), notes: z.string() }),
  charts: z.array(chartImageSchema),
  integrity: integritySchema.optional(),
});
export type EnterpriseAssessmentReport = z.infer<typeof enterpriseAssessmentReportSchema>;

export function severityRank(severity: Severity): number {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[severity] ?? 0;
}

export function normalizeSeverity(value: string): Severity {
  const v = (value || '').toLowerCase();
  if (v.includes('critical')) return 'critical';
  if (v.includes('high')) return 'high';
  if (v.includes('medium') || v.includes('moderate')) return 'medium';
  if (v.includes('low')) return 'low';
  return 'info';
}
