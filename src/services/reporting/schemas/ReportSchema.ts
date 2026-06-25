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
export const costForecastSchema = z.object({
  lines: z.array(costLineSchema),
  totalUsd: z.number(),
  projectedRiskReductionValueUsd: z.number(),
});
export type CostForecast = z.infer<typeof costForecastSchema>;

export const riskForecastSchema = z.object({
  currentRisk: z.number(),
  targetRisk: z.number(),
  reductionPct: z.number(),
  residualRisk: z.number(),
  month12: z.number(),
  month24: z.number(),
  month36: z.number(),
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
export const riskWeightSchema = z.object({ domain: z.string(), weightPct: z.number(), score: z.number(), contributionPct: z.number() });
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
export const costLineDetailSchema = z.object({ category: z.string(), hours: z.number(), engineers: z.number(), rateUsd: z.number(), costUsd: z.number(), formula: z.string() });
export const costBreakdownSchema = z.object({ blendedRateUsd: z.number(), totalHours: z.number(), totalUsd: z.number(), lines: z.array(costLineDetailSchema) });
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
export const impactReasonSchema = z.object({ dimension: z.string(), level: z.string(), reason: z.string() });
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

// Phase 10 — Executive Decision Center™
export const executiveDecisionSchema = z.object({ decision: z.string(), type: z.string(), rationale: z.string(), owner: z.string() });
export type ExecutiveDecision = z.infer<typeof executiveDecisionSchema>;

// Phase 11 — Enterprise Remediation Playbook™
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
});
export type PlaybookDetail = z.infer<typeof playbookDetailSchema>;

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
});
export type ComplianceMapping = z.infer<typeof complianceMappingSchema>;

export const roadmapPhaseSchema = z.object({
  phase: z.string(),
  description: z.string(),
  status: z.string(),
  effortWeeks: z.number(),
});
export type RoadmapPhase = z.infer<typeof roadmapPhaseSchema>;

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

export const enterpriseAssessmentReportSchema = z.object({
  meta: reportMetaSchema,
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
  playbookDetail: z.array(playbookDetailSchema),
  waveSimulation: z.array(waveSimulationSchema),
  governanceGates: z.array(governanceGateSchema),
  explainability: z.array(explainabilitySchema),
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
  evidence: z.object({ sources: z.array(z.string()), notes: z.string() }),
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
